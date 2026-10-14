//! Verified process leases and the production credential execution boundary.

use super::{ApprovalInput, Error, Execution, FullRequest, RemoteHelper, RequestRunner, Result};
use kv_core::remote::canonical::{sha256_hex, CanonicalAction, CanonicalAgent, CanonicalRequest};
use kv_core::remote::*;
use kv_core::{AuthorizeGate, ClientContext, SessionAuth};
use kv_ipc::Op;
use kv_platform::Confirmer;
use kv_vault::Vault;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub type Task<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub trait OwnerUi: Send + Sync {
    fn request(&self, op: &'static str, fields: Value) -> Task<'_, Value>;
}

/// Only the authenticated private agent may supply these fixed presentation facts.
/// A missing/unknown reply is unavailable, never evidence of a user's cancellation.
pub(super) fn private_ui_error(reply: &Value) -> Error {
    Error(match reply["error"].as_str() {
        Some("remote_action_cancelled") => "user_cancelled",
        Some("remote_request_expired") => "remote_request_expired",
        Some("invalid_remote_request") => "invalid_remote_request",
        Some("invalid_remote_scope") => "invalid_remote_scope",
        Some("invalid_remote_response") => "invalid_remote_response",
        Some("approval_key_unavailable") => "approval_key_unavailable",
        Some("remote_helper_unavailable") => "remote_helper_unavailable",
        Some("remote_setting_unavailable") => "remote_setting_unavailable",
        _ => "remote_ui_unavailable",
    })
}

fn owner_operation_text(reason: &str) -> String {
    let (zh, en) = match reason {
        "prepare_grant" => (
            "确认启用远程无人值守授权",
            "Confirm remote unattended authorization",
        ),
        "issue_grant" => ("确认签发远程授权", "Confirm issuing remote authorization"),
        "pair_start" => ("确认添加远程设备", "Confirm adding a remote device"),
        "revoke_grant" => ("确认撤销远程授权", "Confirm revoking remote authorization"),
        "revoke_device" | "revoke_device_proof" => {
            ("确认移除远程设备", "Confirm removing a remote device")
        }
        "remote_settings" => (
            "确认更改 KeyValet 授权设置",
            "Confirm changing KeyValet authorization settings",
        ),
        _ => (
            "确认 KeyValet 远程操作",
            "Confirm KeyValet remote operation",
        ),
    };
    kv_i18n::t(zh, en)
}

// These owner operations always sign an object (or the T2 preparation proof) after
// confirmation. The signature's AK_s userPresence gate supplies Strong; a second,
// unbound LocalAuthentication evaluation neither strengthens nor replaces it.
fn signed_owner_confirmation(reason: &str, binding: &Value) -> Result<(ApprovalLevel, Value)> {
    let (target, mut message, level) = if reason == "issue_directive" {
        let directive = &binding["directive"];
        let level = match binding["minimum_level"].as_str() {
            Some("quick") => ApprovalLevel::Quick,
            Some("strong") => ApprovalLevel::Strong,
            _ => return Err(Error("insufficient_level")),
        };
        let (zh, en) = match directive["op"].as_str() {
            Some("query_status") => ("查看远程状态", "View remote status"),
            Some("query_pending") => ("查看远程待批请求", "View remote pending requests"),
            Some("query_grants") => ("查看远程授权", "View remote grants"),
            Some("query_audit") => ("查看远程审计", "View remote audit"),
            Some("lock") => ("锁定远程凭证库", "Lock the remote vault"),
            Some("revoke_grant") => ("撤销远程授权", "Revoke a remote grant"),
            Some("revoke_all_grants") => ("收回全部远程授权", "Revoke all remote grants"),
            Some("cancel_approval") => ("取消远程待批请求", "Cancel a remote pending request"),
            Some("notify") => ("提醒远程审批者", "Notify the remote approver"),
            Some("set_mode") => ("更改远程审批模式", "Change the remote approval mode"),
            Some("set_unlock_ttl") => ("更改远程解锁期限", "Change the remote unlock duration"),
            Some("set_class") => ("更改远程审批类别", "Change the remote approval class"),
            Some("set_device_label") => ("更改远程设备名称", "Rename the remote device"),
            Some("revoke_device") => ("移除远程设备", "Remove a remote device"),
            _ => return Err(Error("invalid_directive")),
        };
        (directive["aud"].as_str(), kv_i18n::t(zh, en), level)
    } else if reason == "revoke_device_proof" {
        let mut message = owner_operation_text(reason);
        if let Some(label) = binding["label"].as_str() {
            if label.len() > 4096 || label.chars().any(char::is_control) {
                return Err(Error("invalid_device_label"));
            }
            message.push_str(&kv_i18n::t(
                &format!("\n设备名称：{label}"),
                &format!("\nDevice label: {label}"),
            ));
        }
        (
            binding["device_id"].as_str(),
            message,
            ApprovalLevel::Strong,
        )
    } else {
        let intent = &binding["intent"];
        let mut message = owner_operation_text(reason);
        if intent["scope"]["max_tier"] == "T2" {
            message.push_str(&kv_i18n::t(
                "\n含敏感操作（T2）",
                "\nIncludes sensitive operations (T2)",
            ));
        }
        if let Some(credential) = intent["scope"]["credential"].as_str() {
            if credential.len() > 4096 || credential.chars().any(char::is_control) {
                return Err(Error("invalid_grant"));
            }
            message.push_str(&kv_i18n::t(
                &format!("\n凭证：{credential}"),
                &format!("\nCredential: {credential}"),
            ));
        }
        if let (Some(start), Some(end)) = (intent["nbf"].as_i64(), intent["exp"].as_i64()) {
            let seconds = end
                .checked_sub(start)
                .filter(|s| *s > 0)
                .ok_or(Error("invalid_grant"))?;
            message.push_str(&kv_i18n::t(
                &format!("\n授权期限：{seconds} 秒"),
                &format!("\nGrant duration: {seconds} seconds"),
            ));
        } else if intent["exp"].is_null() {
            message.push_str(&kv_i18n::t(
                "\n授权期限：直到撤销",
                "\nGrant duration: until revoked",
            ));
        } else {
            return Err(Error("invalid_grant"));
        }
        (intent["aud"].as_str(), message, ApprovalLevel::Strong)
    };
    let target = target
        .filter(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
        .ok_or(Error("wrong_recipient"))?;
    message.push_str(&if reason == "revoke_device_proof" {
        kv_i18n::t(&format!("\n设备：{target}"), &format!("\nDevice: {target}"))
    } else {
        kv_i18n::t(
            &format!("\n执行端：{target}"),
            &format!("\nExecutor: {target}"),
        )
    });
    Ok((
        level,
        json!({"message":message,"ok_label":kv_i18n::t("确认","Confirm")}),
    ))
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub uid: u32,
    pub pid: u32,
    pub start_time: u64,
    pub exe_sha256: String,
}

pub trait Processes: Send + Sync {
    fn inspect(&self, pid: u32) -> Result<ProcessIdentity>;
}

pub struct SystemProcesses;

#[cfg(target_os = "macos")]
impl Processes for SystemProcesses {
    fn inspect(&self, pid: u32) -> Result<ProcessIdentity> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let length = std::mem::size_of_val(&info) as i32;
        if pid == 0
            || pid > i32::MAX as u32
            || unsafe {
                libc::proc_pidinfo(pid as i32, 3, 0, &mut info as *mut _ as *mut _, length)
            } != length
        {
            return Err(Error("agent_unavailable"));
        }
        let mut path = [0u8; 4096];
        let count =
            unsafe { libc::proc_pidpath(pid as i32, path.as_mut_ptr().cast(), path.len() as u32) };
        if count <= 0 {
            return Err(Error("agent_unavailable"));
        }
        let path =
            std::ffi::CStr::from_bytes_until_nul(&path).map_err(|_| Error("agent_unavailable"))?;
        use std::os::unix::ffi::OsStrExt;
        let bytes = bounded_executable(std::path::Path::new(std::ffi::OsStr::from_bytes(
            path.to_bytes(),
        )))?;
        Ok(ProcessIdentity {
            uid: info.pbi_uid,
            pid,
            start_time: info
                .pbi_start_tvsec
                .saturating_mul(1_000_000)
                .saturating_add(info.pbi_start_tvusec),
            exe_sha256: bytes,
        })
    }
}

#[cfg(target_os = "linux")]
impl Processes for SystemProcesses {
    fn inspect(&self, pid: u32) -> Result<ProcessIdentity> {
        super::process_observer::observe(
            pid,
            inspect_local_linux_process,
            super::process::inspect_linux_agent,
        )
    }
}

#[cfg(target_os = "linux")]
fn inspect_local_linux_process(pid: u32) -> Result<ProcessIdentity> {
    use std::os::unix::fs::MetadataExt;
    if pid == 0 {
        return Err(Error("agent_unavailable"));
    }
    let directory = std::path::PathBuf::from(format!("/proc/{pid}"));
    let uid = std::fs::metadata(&directory)
        .map_err(|_| Error("agent_unavailable"))?
        .uid();
    let start_time =
        kv_platform::peer::process_start_time(pid).map_err(|_| Error("agent_unavailable"))?;
    let path = std::fs::read_link(directory.join("exe")).map_err(|_| Error("agent_unavailable"))?;
    let bytes = bounded_executable(&path)?;
    Ok(ProcessIdentity {
        uid,
        pid,
        start_time,
        exe_sha256: bytes,
    })
}

#[cfg(windows)]
impl Processes for SystemProcesses {
    fn inspect(&self, pid: u32) -> Result<ProcessIdentity> {
        let peer =
            kv_platform::peer::identity_for_pid(pid).map_err(|_| Error("agent_unavailable"))?;
        let owner = kv_platform::trust::load_owner_sid(std::path::Path::new(
            kv_platform::paths::OWNER_SID_FILE,
        ))
        .map_err(|_| Error("agent_unavailable"))?;
        if !kv_platform::peer::sid_equal(&peer.sid, &owner) {
            return Err(Error("agent_identity_mismatch"));
        }
        let bytes = bounded_executable(&peer.exe_path)?;
        let start_time =
            kv_platform::peer::process_start_time(pid).map_err(|_| Error("agent_unavailable"))?;
        Ok(ProcessIdentity {
            uid: 0,
            pid,
            start_time,
            exe_sha256: bytes,
        })
    }
}

fn bounded_executable(path: &std::path::Path) -> Result<String> {
    use std::io::Read;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    if std::fs::symlink_metadata(path)
        .map_err(|_| Error("agent_unavailable"))?
        .file_type()
        .is_symlink()
    {
        return Err(Error("agent_unavailable"));
    }
    let mut file = options.open(path).map_err(|_| Error("agent_unavailable"))?;
    let metadata = file.metadata().map_err(|_| Error("agent_unavailable"))?;
    const LIMIT: u64 = 1024 * 1024 * 1024;
    if !metadata.is_file() || metadata.len() > LIMIT {
        return Err(Error("agent_unavailable"));
    }
    let (digest, count) = kv_core::remote::canonical::sha256_reader(file.by_ref().take(LIMIT + 1))
        .map_err(|_| Error("agent_unavailable"))?;
    let after = file.metadata().map_err(|_| Error("agent_unavailable"))?;
    if count != metadata.len()
        || after.len() != metadata.len()
        || after.modified().ok() != metadata.modified().ok()
    {
        return Err(Error("agent_unavailable"));
    }
    Ok(digest)
}

pub trait SessionExecutor: Send + Sync {
    fn vault(&self) -> &Vault;
    fn context(&self) -> &ClientContext;
    fn execute(&self, op: Op, params: Map<String, Value>, binding: String) -> Task<'_, Value>;
    fn authorize(&self, reason: String) -> Task<'_, ApprovalLevel>;
    fn close(&self);
}

pub struct CredentialSession<G, C> {
    pub vault: Arc<Vault>,
    pub context: ClientContext,
    pub auth: Arc<tokio::sync::Mutex<SessionAuth<G>>>,
    pub confirmer: C,
}

impl<G: AuthorizeGate + Send + Sync, C: Confirmer + Send + Sync> SessionExecutor
    for CredentialSession<G, C>
{
    fn vault(&self) -> &Vault {
        &self.vault
    }
    fn context(&self) -> &ClientContext {
        &self.context
    }
    fn execute(&self, op: Op, params: Map<String, Value>, binding: String) -> Task<'_, Value> {
        let params = kv_vault::SecretJson(Value::Object(params));
        Box::pin(async move {
            let mut auth = self.auth.lock().await;
            let result = kv_core::dispatch::dispatch_approved(
                &self.vault,
                op,
                params.as_object().unwrap(),
                &binding,
                &self.context,
                Some(&mut auth),
                &self.confirmer,
            )
            .await
            .map_err(|_| Error("credential_operation_failed"));
            result
        })
    }
    fn authorize(&self, reason: String) -> Task<'_, ApprovalLevel> {
        Box::pin(async move {
            self.auth
                .lock()
                .await
                .authorize(&reason)
                .await
                .map_err(|error| {
                    // The authenticated agent supplies typed facts. Do not infer a denial
                    // or cancellation from localized prose or a failed biometric operation.
                    if let Ok(value) = serde_json::from_str::<Value>(&error) {
                        match value["code"].as_str() {
                            Some("local_approval_denied") => return Error("local_approval_denied"),
                            Some("local_approval_cancelled") => {
                                return Error("local_approval_cancelled")
                            }
                            Some("local_approval_failed") => return Error("local_approval_failed"),
                            Some("local_approval_timeout") => {
                                return Error("local_approval_timeout")
                            }
                            _ => {}
                        }
                    }
                    let lower = error.to_ascii_lowercase();
                    if lower.contains("timeout")
                        || lower.contains("timed out")
                        || error.contains("超时")
                    {
                        Error("local_approval_timeout")
                    } else {
                        Error("local_approval_unavailable")
                    }
                })?;
            Ok(ApprovalLevel::Strong)
        })
    }
    fn close(&self) {
        self.vault.close();
    }
}

struct Lease {
    agent: ProcessIdentity,
    deadline: Instant,
    executor: Arc<dyn SessionExecutor>,
}

pub struct ProductionRunner {
    processes: Arc<dyn Processes>,
    leases: Mutex<HashMap<String, Lease>>,
    aliases: Mutex<HashMap<String, String>>,
    owner_ui: Mutex<Option<Arc<dyn OwnerUi>>>,
}

impl ProductionRunner {
    pub fn new(processes: Arc<dyn Processes>) -> Arc<Self> {
        Arc::new(Self {
            processes,
            leases: Mutex::new(HashMap::new()),
            aliases: Mutex::new(HashMap::new()),
            owner_ui: Mutex::new(None),
        })
    }
    pub fn set_owner_ui(&self, ui: Option<Arc<dyn OwnerUi>>) -> Result<()> {
        *self
            .owner_ui
            .lock()
            .map_err(|_| Error("state_unavailable"))? = ui;
        Ok(())
    }
    pub fn attach(
        &self,
        session: String,
        uid: u32,
        pid: u32,
        ttl: Duration,
        executor: Arc<dyn SessionExecutor>,
    ) -> Result<()> {
        let agent = self.processes.inspect(pid)?;
        if agent.uid != uid || session.is_empty() || ttl.is_zero() {
            return Err(Error("agent_identity_mismatch"));
        }
        let mut leases = self.leases.lock().map_err(|_| Error("state_unavailable"))?;
        if leases.len() >= 128 || leases.contains_key(&session) {
            return Err(Error("session_unavailable"));
        }
        leases.insert(
            session,
            Lease {
                agent,
                deadline: Instant::now() + ttl.min(Duration::from_secs(86400)),
                executor,
            },
        );
        Ok(())
    }
    fn lease(&self, session: &str) -> Result<(ProcessIdentity, Arc<dyn SessionExecutor>)> {
        let session = self
            .aliases
            .lock()
            .map_err(|_| Error("state_unavailable"))?
            .get(session)
            .cloned()
            .unwrap_or_else(|| session.into());
        let mut leases = self.leases.lock().map_err(|_| Error("state_unavailable"))?;
        leases.retain(|_, lease| {
            let alive = lease.deadline > Instant::now()
                && self
                    .processes
                    .inspect(lease.agent.pid)
                    .is_ok_and(|agent| agent == lease.agent);
            if !alive {
                lease.executor.close();
            }
            alive
        });
        let lease = leases.get(&session).ok_or(Error("session_expired"))?;
        Ok((lease.agent.clone(), lease.executor.clone()))
    }

    pub fn rebind(&self, original: &CanonicalRequest, current: &str) -> Result<()> {
        let (agent, _) = self.lease(current)?;
        if agent.uid != original.agent.uid
            || agent.pid != original.agent.pid
            || agent.exe_sha256 != original.agent.exe_sha256
            || original
                .agent
                .extra
                .get("start_time")
                .and_then(Value::as_u64)
                != Some(agent.start_time)
        {
            return Err(Error("agent_identity_mismatch"));
        }
        let old = original
            .extra
            .get("session_id")
            .and_then(Value::as_str)
            .ok_or(Error("session_unavailable"))?;
        if old != current && self.lease(old).is_err() {
            let mut aliases = self
                .aliases
                .lock()
                .map_err(|_| Error("state_unavailable"))?;
            if aliases.len() >= 128 {
                return Err(Error("session_unavailable"));
            }
            aliases.insert(old.into(), current.into());
        }
        Ok(())
    }
    pub fn sweep(&self) {
        let _ = self.lease("");
        if let Ok(leases) = self.leases.lock() {
            if let Ok(mut aliases) = self.aliases.lock() {
                aliases.retain(|_, target| leases.contains_key(target));
            }
        }
    }

    pub fn prepare(
        &self,
        helper: &RemoteHelper,
        session: &str,
        op: &str,
        mut params: Map<String, Value>,
        local_channel: bool,
    ) -> Result<(ApprovalInput, Vec<String>, Vec<String>)> {
        let (agent, executor) = self.lease(session)?;
        let operation = Op::parse(op).ok_or(Error("invalid_operation"))?;
        if !matches!(
            operation,
            Op::Get
                | Op::AccessToken
                | Op::Totp
                | Op::Aws
                | Op::HttpRequest
                | Op::HttpTest
                | Op::GatewayOpen
        ) {
            return Err(Error("policy_denied_t3"));
        }
        let ty = params
            .get("type")
            .and_then(Value::as_str)
            .ok_or(Error("invalid_credential"))?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or(Error("invalid_credential"))?;
        let (ty, name, record) = executor
            .vault()
            .get_record(ty, name)
            .map_err(|_| Error("invalid_credential"))?;
        let purpose = kv_ipc::clean_purpose(params.get("purpose").and_then(Value::as_str))
            .ok_or(Error("purpose_required"))?;
        for key in [
            "approval_id",
            "runtime_budget_s",
            "wait_in_call_ms",
            "agent",
            "viaProxy",
        ] {
            params.remove(key);
        }
        params.insert("type".into(), json!(ty));
        params.insert("name".into(), json!(name));
        params.insert("purpose".into(), json!(purpose));
        let binding = kv_core::dispatch::operation_binding(executor.vault(), operation, &params)
            .map_err(|_| Error("invalid_credential"))?;
        let mut extra = Map::new();
        extra.insert("credential_binding".into(), json!(binding));
        if let Some(frontend) = params.get("frontend") {
            let continuation: kv_ipc::continuation::FrontendContinuation =
                serde_json::from_value(frontend.clone())?;
            if !continuation.validate() || continuation.op != op {
                return Err(Error("invalid_continuation"));
            }
            extra.insert("frontend".into(), frontend.clone());
        }
        let credential = format!("{ty}/{name}");
        let mut canonical = CanonicalRequest {
            v: 1,
            kind: ApprovalKind::Use,
            requester: helper.local.device_id.clone(),
            credential: Some(credential.clone()),
            action: CanonicalAction {
                kind: op.into(),
                extra: Default::default(),
            },
            method: None,
            host: None,
            path: None,
            query_keys: vec![],
            body_sha256: None,
            headers_digest: None,
            agent: CanonicalAgent {
                runtime: executor
                    .context()
                    .client
                    .clone()
                    .unwrap_or_else(|| "unknown".into()),
                repo_or_cwd: executor.context().cwd.clone().unwrap_or_default(),
                uid: agent.uid,
                pid: agent.pid,
                exe_sha256: agent.exe_sha256,
                extra: json!({"start_time":agent.start_time})
                    .as_object()
                    .unwrap()
                    .clone(),
            },
            purpose,
            nonce: String::new(),
            exp: 0,
            extra,
        };
        let mut tier = if operation == Op::Totp {
            Tier::T1
        } else {
            Tier::T2
        };
        let mut display_operation = None;
        let hosts = record
            .http
            .as_ref()
            .map_or_else(Vec::new, |http| http.allowed_hosts.clone());
        if matches!(operation, Op::HttpRequest | Op::HttpTest) {
            let test = record.http.as_ref().and_then(|http| http.test.as_ref());
            let method = if operation == Op::HttpTest {
                test.map(|test| test.method.as_str())
            } else {
                params.get("method").and_then(Value::as_str)
            };
            let url = if operation == Op::HttpTest {
                test.map(|test| test.url.as_str())
            } else {
                params.get("url").and_then(Value::as_str)
            }
            .ok_or(Error("invalid_http_request"))?;
            let (method, url) = kv_proxy::proxy::precheck_request(&record, method, url)
                .map_err(|_| Error("invalid_http_request"))?;
            let body = params.get("body").filter(|v| !v.is_null()).map(|v| {
                v.as_str()
                    .map(str::as_bytes)
                    .map(Vec::from)
                    .unwrap_or_else(|| serde_json::to_vec(v).unwrap())
            });
            if body.as_ref().is_some_and(|body| {
                body.len() > 1024 * 1024 || matches!(method.as_str(), "GET" | "HEAD")
            }) {
                return Err(Error("invalid_http_request"));
            }
            canonical.method = Some(method.clone());
            canonical.host = url.host_str().map(str::to_owned);
            canonical.path = Some(url.path().into());
            canonical.query_keys = url.query_pairs().map(|(key, _)| key.into_owned()).collect();
            if let Some(query) = params.get("query").and_then(Value::as_object) {
                canonical.query_keys.extend(query.keys().cloned());
            }
            canonical.body_sha256 = body.as_ref().map(|body| sha256_hex(body));
            canonical.headers_digest = params
                .get("headers")
                .map(|headers| {
                    kv_core::remote::canonical::jcs(headers).map(|bytes| sha256_hex(&bytes))
                })
                .transpose()?;
            tier = if matches!(method.as_str(), "GET" | "HEAD") {
                Tier::T1
            } else {
                Tier::T2
            };
            display_operation = Some(Operation {
                summary: format!(
                    "{method} {}{}",
                    canonical.host.as_deref().unwrap_or_default(),
                    url.path()
                ),
                method,
                host: canonical.host.clone().unwrap_or_default(),
                path: url.path().into(),
                query_keys: canonical.query_keys.clone(),
                body_bytes: body.as_ref().map_or(0, |body| body.len() as u64),
                extra: Default::default(),
            });
        }
        let min_level = if tier == Tier::T2 {
            ApprovalLevel::Strong
        } else {
            ApprovalLevel::Quick
        };
        let requested_scope = match kv_core::read_settings(&executor.vault().dir).grant_mode {
            kv_core::GrantMode::PerUse => ScopeOption::PerUse,
            kv_core::GrantMode::PerCredential => ScopeOption::PerCredential,
            kv_core::GrantMode::PerSession => ScopeOption::PerSession,
            kv_core::GrantMode::Remember => ScopeOption::Remember1h,
        };
        let input = ApprovalInput {
            canonical,
            credential: Some(Credential {
                r#ref: credential.clone(),
                kind: serde_json::from_value(json!(record.kind_or_static().as_str()))?,
                display: credential,
                proxy_only: record.http.as_ref().is_some_and(|http| http.proxy_only),
                extra: Default::default(),
            }),
            operation: display_operation,
            tier,
            min_level,
            scope_options: if tier == Tier::T2 {
                vec![ScopeOption::PerUse]
            } else {
                vec![ScopeOption::PerUse, requested_scope]
            },
            requested_scope: if tier == Tier::T2 {
                ScopeOption::PerUse
            } else {
                requested_scope
            },
            session_id: session.into(),
            full_request: FullRequest::new(op, params)?,
            auto_allowed: false,
            local_channel_available: local_channel,
        };
        Ok((
            input,
            hosts,
            vec![
                "GET".into(),
                "HEAD".into(),
                "POST".into(),
                "PUT".into(),
                "PATCH".into(),
                "DELETE".into(),
            ],
        ))
    }
}

impl RequestRunner for ProductionRunner {
    fn has_private_ui(&self) -> bool {
        self.owner_ui.lock().is_ok_and(|ui| ui.is_some())
    }
    fn private_ui(&self, op: &'static str, fields: Value) -> Task<'_, Value> {
        Box::pin(async move {
            let ui = self
                .owner_ui
                .lock()
                .map_err(|_| Error("state_unavailable"))?
                .clone()
                .ok_or(Error("remote_ui_unavailable"))?;
            ui.request(op, fields).await
        })
    }
    fn execute(&self, request: Execution) -> Task<'_, Value> {
        Box::pin(async move {
            let session = request
                .canonical
                .extra
                .get("session_id")
                .and_then(Value::as_str)
                .ok_or(Error("session_unavailable"))?;
            let (agent, executor) = self.lease(session)?;
            if agent.uid != request.canonical.agent.uid
                || agent.pid != request.canonical.agent.pid
                || agent.exe_sha256 != request.canonical.agent.exe_sha256
                || request
                    .canonical
                    .agent
                    .extra
                    .get("start_time")
                    .and_then(Value::as_u64)
                    != Some(agent.start_time)
            {
                return Err(Error("agent_identity_mismatch"));
            }
            let binding = request
                .canonical
                .extra
                .get("credential_binding")
                .and_then(Value::as_str)
                .ok_or(Error("invalid_execution_binding"))?;
            if request.full_request.op == "gatewayForward" {
                let params = request.full_request.params()?;
                if kv_core::dispatch::operation_binding(executor.vault(), Op::HttpRequest, &params)
                    .map_err(|_| Error("invalid_execution_binding"))?
                    != binding
                {
                    return Err(Error("invalid_execution_binding"));
                }
                return Ok(json!({"http_forward_authorized":true}));
            }
            let op = Op::parse(&request.full_request.op).ok_or(Error("invalid_operation"))?;
            executor
                .execute(op, request.full_request.params()?, binding.into())
                .await
        })
    }
    fn agent_alive(&self, uid: u32, pid: u32, hash: &str) -> bool {
        self.leases.lock().is_ok_and(|leases| {
            leases.values().any(|lease| {
                lease.agent.uid == uid
                    && lease.agent.pid == pid
                    && lease.agent.exe_sha256 == hash
                    && lease.deadline > Instant::now()
                    && self
                        .processes
                        .inspect(pid)
                        .is_ok_and(|agent| agent == lease.agent)
            })
        })
    }
    fn lock_sessions(&self) -> Result<()> {
        self.aliases
            .lock()
            .map_err(|_| Error("state_unavailable"))?
            .clear();
        for (_, lease) in self
            .leases
            .lock()
            .map_err(|_| Error("state_unavailable"))?
            .drain()
        {
            lease.executor.close();
        }
        Ok(())
    }
    fn local_authorize(&self, reason: &'static str, binding: Value) -> Task<'_, ApprovalLevel> {
        Box::pin(async move {
            if self.has_private_ui() && binding.get("session_id").is_none() {
                if reason == "remote_decide" {
                    let mut request = binding["request"].clone();
                    if let Some(option) = binding["scope_option"].as_str() {
                        request["requested_scope"] = json!(option);
                        request["scope_options"] = json!([option]);
                    }
                    if binding["minimum_level"] == "strong" {
                        request["min_level"] = json!("strong");
                    }
                    let reply = self
                        .private_ui(
                            "remote_approval",
                            json!({"request":request,
                        "context":{"now":kv_platform::presence::unix_seconds(),"unattended":binding["unattended"]}}),
                        )
                        .await?;
                    let params = &reply["params"];
                    if reply["ok"] != true {
                        return Err(private_ui_error(&reply));
                    }
                    if params["approval_id"] != binding["request"]["approval_id"]
                        || params["decision"] != binding["decision"]
                        || params["scope"]["mode"] != binding["scope"]["mode"]
                        || params["scope"]["level"] != binding["scope"]["level"]
                    {
                        return Err(Error("invalid_remote_response"));
                    }
                    return Ok(
                        if binding["minimum_level"] == "strong"
                            || binding["request"]["min_level"] == "strong"
                            || binding["request"]["kind"] != "use"
                            || binding["scope"]["mode"] == "standing"
                        {
                            ApprovalLevel::Strong
                        } else {
                            ApprovalLevel::Quick
                        },
                    );
                }
                if binding["intent"]["aud"] == "*" {
                    let reply = self.private_ui("remote_confirm_global", json!({})).await?;
                    if reply["ok"] != true {
                        return Err(private_ui_error(&reply));
                    }
                    if reply["confirmed"] != true {
                        return Err(if reply["confirmed"] == false {
                            Error("user_cancelled")
                        } else {
                            Error("invalid_remote_response")
                        });
                    }
                }
                if matches!(
                    reason,
                    "issue_grant" | "prepare_grant" | "revoke_device_proof"
                ) || (reason == "issue_directive" && binding.get("directive").is_some())
                {
                    let (minimum, fields) = signed_owner_confirmation(reason, &binding)?;
                    // The authenticated owner's explicit query is the UI action. A
                    // paginated metadata read must not reopen a dialog for every page.
                    // publish_directive still requires the original unlocked AK_q,
                    // verifies its signature and applies the normal role/nonce/exp rules.
                    if reason == "issue_directive"
                        && minimum == ApprovalLevel::Quick
                        && matches!(
                            binding["directive"]["op"].as_str(),
                            Some("query_status" | "query_pending" | "query_grants" | "query_audit")
                        )
                    {
                        return Ok(ApprovalLevel::Quick);
                    }
                    let reply = self.private_ui("confirm", fields).await?;
                    return match reply["confirmed"].as_bool() {
                        Some(true) => Ok(minimum),
                        Some(false) => Err(Error("user_cancelled")),
                        None => Err(Error("invalid_remote_response")),
                    };
                }
                let reply = self
                    .private_ui(
                        "authenticate",
                        json!({
                            "reason":owner_operation_text(reason),
                            "cancel":kv_i18n::t("取消","Cancel")
                        }),
                    )
                    .await?;
                if reply["outcome"] != "approved" {
                    return Err(match reply["outcome"].as_str() {
                        Some("failed") => Error("authentication_failed"),
                        Some("timeout") => Error("authentication_timeout"),
                        Some("cancelled") => Error("authentication_cancelled"),
                        _ => Error("authentication_unavailable"),
                    });
                }
                // Hardware-bound AK_s/AK_q signing follows this UI step in the helper.
                return Ok(ApprovalLevel::Strong);
            }
            let session = binding["session_id"]
                .as_str()
                .ok_or(Error("session_unavailable"))?;
            let (_, executor) = self.lease(session)?;
            executor
                .authorize(format!("Approve KeyValet operation\n{}", binding))
                .await
        })
    }
}
