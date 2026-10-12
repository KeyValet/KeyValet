//! A remote connection never authenticates or opens a credential session.
use super::ipc::CallerContext;
use super::{Error, RemoteHelper, Result};
use kv_core::remote::canonical::from_json;
use kv_ipc::remote::{allowed_ops, Caller, Request, Response};
use serde_json::{json, Value};
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

// The vault bootstrap installs a fully verified directory and providers atomically. Missing
// metadata is an unavailable remote backend, never an invitation to generate substitute keys.
struct Runtime {
    helper: std::sync::RwLock<Arc<RemoteHelper>>,
    runner: Option<Arc<super::production::ProductionRunner>>,
    authority: Option<Arc<kv_proxy::certificates::CertificateAuthority>>,
    _settings: Option<kv_core::settings::SettingsBinding>,
}
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub fn install_runtime(helper: Arc<RemoteHelper>) -> Result<()> {
    install(helper, None, None)
}

pub fn install_production_runtime(
    helper: Arc<RemoteHelper>,
    runner: Arc<super::production::ProductionRunner>,
    authority: Arc<kv_proxy::certificates::CertificateAuthority>,
) -> Result<()> {
    install(helper, Some(runner), Some(authority))
}

fn install(
    helper: Arc<RemoteHelper>,
    runner: Option<Arc<super::production::ProductionRunner>>,
    authority: Option<Arc<kv_proxy::certificates::CertificateAuthority>>,
) -> Result<()> {
    tokio::runtime::Handle::try_current().map_err(|_| Error("runtime_unavailable"))?;
    let settings = if runner.is_some() {
        Some(super::settings::install(
            &helper,
            std::path::Path::new(kv_platform::paths::VAULT_DIR),
        )?)
    } else {
        None
    };
    RUNTIME
        .set(Runtime {
            helper: std::sync::RwLock::new(helper.clone()),
            runner: runner.clone(),
            authority,
            _settings: settings,
        })
        .map_err(|_| Error("remote_already_initialized"))?;
    #[cfg(any(target_os = "macos", windows))]
    kv_platform::agent::set_remote_identity(helper.local.device_id.clone());
    if helper.services.runner.has_private_ui() {
        let helper = helper.clone();
        tokio::spawn(async move {
            let _ = helper
                .services
                .runner
                .private_ui(
                    "remote_identity",
                    json!({"device_id":helper.local.device_id}),
                )
                .await;
        });
    }
    drop(helper.start_timer());
    if let Some(runner) = runner {
        let runner = Arc::downgrade(&runner);
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                timer.tick().await;
                let Some(runner) = runner.upgrade() else {
                    break;
                };
                runner.sweep();
            }
        });
    }
    Ok(())
}

pub fn runtime() -> Option<Arc<RemoteHelper>> {
    RUNTIME
        .get()
        .and_then(|runtime| runtime.helper.read().ok().map(|helper| helper.clone()))
}

pub(crate) fn replace_helper(expected: &Arc<RemoteHelper>, next: Arc<RemoteHelper>) -> Result<()> {
    let runtime = RUNTIME.get().ok_or(Error("remote_unavailable"))?;
    let mut current = runtime
        .helper
        .write()
        .map_err(|_| Error("state_unavailable"))?;
    if !Arc::ptr_eq(&current, expected) {
        return Err(Error("remote_identity_changed"));
    }
    expected
        .state
        .lock()
        .map_err(|_| Error("state_unavailable"))?
        .retired = true;
    *current = next.clone();
    drop(next.start_timer());
    Ok(())
}

pub fn production_runner() -> Option<Arc<super::production::ProductionRunner>> {
    RUNTIME.get().and_then(|runtime| runtime.runner.clone())
}

pub fn certificate_authority() -> Option<Arc<kv_proxy::certificates::CertificateAuthority>> {
    RUNTIME.get().and_then(|runtime| runtime.authority.clone())
}

pub async fn serve<R: AsyncRead + Unpin + Send, W: AsyncWrite + Unpin + Send>(
    mut reader: R,
    mut writer: W,
    context: CallerContext,
    helper: Option<Arc<RemoteHelper>>,
) -> Result<()> {
    serve_stream(&mut reader, &mut writer, context, helper).await
}

async fn serve_stream(
    reader: &mut (dyn AsyncRead + Unpin + Send),
    mut writer: &mut (dyn AsyncWrite + Unpin + Send),
    context: CallerContext,
    helper: Option<Arc<RemoteHelper>>,
) -> Result<()> {
    let mut reader = BufReader::new(reader);
    let mut seen = std::collections::HashSet::new();
    let mut notifications = false;
    loop {
        // Keep an incomplete frame alive while writing notifications. Cancelling read_frame
        // on every notice would discard bytes already removed from the buffered reader.
        let frame = {
            let frame = read_frame(&mut reader);
            tokio::pin!(frame);
            loop {
                let notice = async {
                    match &helper {
                        Some(helper) if notifications => {
                            helper.next_approval_notice(context, &mut seen).await
                        }
                        _ => std::future::pending::<Result<Value>>().await,
                    }
                };
                tokio::select! {
                    frame = &mut frame => break frame,
                    notice = notice => write(&mut writer, &notice?).await?,
                }
            }
        };
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                audit_failure(&helper, error)?;
                return Err(error);
            }
        };
        let Some(frame) = frame else {
            return Ok(());
        };
        let value: Value = match from_json(&frame) {
            Ok(value) => value,
            Err(_) => {
                audit_failure(&helper, Error("invalid_json"))?;
                write(
                    &mut writer,
                    &json!({"ok":false,"error":{"code":"invalid_json","message":"invalid_json"}}),
                )
                .await?;
                return Err(Error("invalid_json"));
            }
        };
        if value["op"] == "relay" {
            if context.role() != Caller::RelayClient
                || value["protocol"].as_u64() != Some(kv_ipc::PROTOCOL_VERSION as u64)
            {
                audit_failure(&helper, Error("forbidden"))?;
                write(
                    &mut writer,
                    &json!({"ready":false,"protocol":kv_ipc::PROTOCOL_VERSION,"error":"forbidden"}),
                )
                .await?;
                return Err(Error("forbidden"));
            }
            write(
                &mut writer,
                &json!({"ready":true,"protocol":kv_ipc::PROTOCOL_VERSION}),
            )
            .await?;
            continue;
        }
        let request: Request = match from_json(&frame) {
            Ok(request) => request,
            Err(_) => {
                audit_failure(&helper, Error("invalid_remote_op"))?;
                write(&mut writer, &json!({"id":value["id"],"ok":false,"error":{"code":"invalid_remote_op","message":"invalid_remote_op"}})).await?;
                return Err(Error("invalid_remote_op"));
            }
        };
        // Unary Appendix C clients retain response-only framing unless they opt in.
        notifications |= context.role() == Caller::Mcp
            && request.extra.get("notifications").and_then(Value::as_bool) == Some(true);
        let id = request.extra.get("id").and_then(Value::as_u64);
        let helper = helper
            .as_ref()
            .filter(|helper| helper.state.lock().is_ok_and(|state| !state.retired))
            .cloned()
            .or_else(runtime);
        let response = async {
            if request.op == kv_ipc::remote::Op::AccountRecover {
                return match super::startup::recover(context, helper.clone(), request.params).await
                {
                    Ok(value) => Response::ok(value),
                    Err(error) => Response::err(error.code(), error.code()),
                };
            }
            if super::relay_control::is_control(request.op) {
                return super::relay_control::handle(context.role(), request.op, request.params)
                    .await;
            }
            match &helper {
                Some(helper) => helper.handle(context, request).await,
                None if !allowed_ops(context.role()).contains(&request.op) => {
                    Response::err("forbidden", "forbidden")
                }
                None if matches!(
                    request.op,
                    kv_ipc::remote::Op::PairStart | kv_ipc::remote::Op::PairComplete
                ) =>
                {
                    match super::startup::initialize_pair(context, request.op, request.params).await
                    {
                        Ok(result) => Response::ok(result),
                        Err(error) => Response::err(error.code(), error.code()),
                    }
                }
                None => Response::err("remote_unavailable", "remote_unavailable"),
            }
        };
        // A cold wait also observes EOF. fill_buf never consumes the next request,
        // so cancelling this probe cannot discard a partial IPC frame. Pipelined
        // data remains buffered until the current response has been written.
        let disconnected = async {
            let bytes = reader
                .fill_buf()
                .await
                .map_err(|_| Error("ipc_unavailable"))?;
            if bytes.is_empty() {
                Ok(())
            } else {
                std::future::pending::<Result<()>>().await
            }
        };
        let response = tokio::select! {
            biased;
            response = response => response,
            closed = disconnected => {
                if let Err(error) = closed {
                    audit_failure(&helper, error)?;
                    return Err(error);
                }
                return Ok(());
            },
        };
        let mut value = serde_json::to_value(response)?;
        if let Some(id) = id {
            value["id"] = json!(id);
        }
        let result = write(&mut writer, &value).await;
        kv_vault::scrub_json(&mut value);
        result?;
    }
}

/// The established credential session uses the same notification contract as cold MCP IPC.
pub async fn push_approval_notices<W: AsyncWrite + Unpin>(
    helper: &RemoteHelper,
    context: CallerContext,
    writer: &tokio::sync::Mutex<W>,
) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    loop {
        let notice = helper.next_approval_notice(context, &mut seen).await?;
        write(&mut *writer.lock().await, &notice).await?;
    }
}

fn audit_failure(helper: &Option<Arc<RemoteHelper>>, error: Error) -> Result<()> {
    if let Some(helper) = helper {
        let state = helper.lock()?;
        helper.reject(&state, "ipc_rejected", error, "")?;
    }
    Ok(())
}

pub async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let mut frame = Zeroizing::new(Vec::new());
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|_| Error("ipc_unavailable"))?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(Error("truncated_frame"))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |index| index + 1);
        if frame.len().saturating_add(count) > kv_ipc::MAX_LINE_BYTES {
            return Err(Error("payload_too_large"));
        }
        frame.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline.is_some() {
            frame.pop();
            return Ok(Some(frame));
        }
    }
}

async fn write<W: AsyncWrite + Unpin>(writer: &mut W, value: &Value) -> Result<()> {
    let mut bytes = Zeroizing::new(serde_json::to_vec(value)?);
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|_| Error("ipc_unavailable"))
}

#[cfg(unix)]
pub use super::process::authenticate_peer;

#[cfg(windows)]
pub use super::process::authenticate_windows_peer;
#[cfg(windows)]
pub use super::process::authenticate_windows_relay_peer;
#[cfg(windows)]
pub use super::process::bind_windows_mcp_worker;
