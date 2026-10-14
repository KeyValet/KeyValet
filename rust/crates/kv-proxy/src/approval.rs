//! Approval waiting shared by the gateway and future transparent-proxy connections.
//! Only the kernel sends keepalives: no HTTP bytes precede the final response.

use bytes::Bytes;
use futures_util::future::BoxFuture;
use http_body_util::{BodyExt, Full};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

pub const HTTP_WAIT: Duration = Duration::from_secs(540);
pub const UNKNOWN_HOST_WAIT: Duration = Duration::from_secs(55);
pub const TCP_KEEPALIVE_INTERVAL_S: i32 = 20;

pub fn http_wait_limit(policy: Duration, host_hint_s: Option<u64>) -> Duration {
    policy.min(
        host_hint_s
            .map(|s| Duration::from_secs(s.saturating_sub(60)))
            .unwrap_or(UNKNOWN_HOST_WAIT),
    )
}

#[derive(Clone)]
pub struct ApprovalRequest {
    pub credential_type: String,
    pub credential_name: String,
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Bytes,
    pub purpose: Option<String>,
}

/// Implemented by the helper's grant policy. authorize must promptly return an approval ID;
/// wait authorizes the retained request without executing HTTP a second time in the helper.
pub trait ApprovalProvider: Send + Sync {
    fn authorize(&self, request: ApprovalRequest) -> BoxFuture<'_, Result<Value, String>>;
    fn wait(&self, approval_id: String, max_wait: Duration)
        -> BoxFuture<'_, Result<Value, String>>;
}

pub type WaitNotice = Arc<dyn Fn(&str, &str) + Send + Sync>;

#[derive(Clone)]
pub struct ApprovalLayer {
    pub provider: Arc<dyn ApprovalProvider>,
    pub http_wait: Duration,
    pub notice: Option<WaitNotice>,
}

impl ApprovalLayer {
    pub async fn authorize(
        &self,
        request: ApprovalRequest,
        hint: Option<u64>,
    ) -> Result<Value, String> {
        self.authorize_observed(request, hint, |_| {}).await
    }

    pub(crate) async fn authorize_observed(
        &self,
        request: ApprovalRequest,
        hint: Option<u64>,
        observe: impl Fn(&Value),
    ) -> Result<Value, String> {
        let deadline = tokio::time::Instant::now() + http_wait_limit(self.http_wait, hint);
        // Receiving an ID is a control-plane exchange, not a blocking authentication prompt.
        let value = tokio::time::timeout(
            Duration::from_secs(5)
                .min(deadline.saturating_duration_since(tokio::time::Instant::now())),
            self.provider.authorize(request),
        )
        .await
        .map_err(|_| "The helper did not return an approval ID".to_string())?;
        let mut value = normalize_local_result(value)?;
        observe(&value);
        if !is_pending(&value) {
            return Ok(value);
        }
        let id = value["approval_id"]
            .as_str()
            .filter(|id| valid_id(id))
            .ok_or_else(|| "The helper returned an invalid approval ID".to_string())?
            .to_owned();
        if let Some(notice) = &self.notice {
            notice(
                value["approver"]["label"]
                    .as_str()
                    .unwrap_or("your approval device"),
                &id,
            );
        }
        if value["relay"] == "offline" {
            return Ok(value);
        }
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(value);
            }
            match tokio::time::timeout_at(deadline, self.provider.wait(id.clone(), remaining)).await
            {
                Err(_) => return Ok(value),
                Ok(Err(error))
                    if error.to_ascii_lowercase().contains("timed out")
                        || error.to_ascii_lowercase().contains("timeout") =>
                {
                    return Ok(value)
                }
                Ok(result) => {
                    let result = normalize_local_result(result)?;
                    if !is_pending(&result) {
                        return Ok(result);
                    }
                    if result["approval_id"].as_str() != Some(&id) {
                        return Err("The helper changed the pending approval ID".into());
                    }
                    value = result;
                }
            }
            // An early reply must not turn an offline helper into a tight polling loop.
            tokio::time::sleep(
                Duration::from_millis(100)
                    .min(deadline.saturating_duration_since(tokio::time::Instant::now())),
            )
            .await;
        }
    }
}

/// Interpret only explicit terminal codes. A dialog/transport timeout with an unexpired
/// approval is still pending; a free-form error never means the user said no.
pub(crate) fn normalize_local_result(result: Result<Value, String>) -> Result<Value, String> {
    result
        .map(|mut value| {
            // Current helper IPC represents a terminal cancellation with an explicit
            // reason on approval_expired. Preserve that distinction on the HTTP side.
            if value["status"] == "approval_expired" && value["reason"] == "cancelled" {
                value["status"] = json!("approval_cancelled");
            }
            value
        })
        .or_else(|error| {
            let value = serde_json::from_str::<Value>(&error).unwrap_or(Value::Null);
            let status = match value["code"]
                .as_str()
                .or_else(|| value["error"]["code"].as_str())
            {
                Some("local_approval_denied") => "approval_denied",
                Some("local_approval_cancelled") => "approval_cancelled",
                Some("local_approval_expired") => "approval_expired",
                Some("local_approval_timeout") => {
                    let Some(expiry) = value["expires_at"].as_i64() else {
                        return Err(error);
                    };
                    if !value["approval_id"].as_str().is_some_and(valid_id) {
                        return Err(error);
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    if expiry <= now {
                        "approval_expired"
                    } else {
                        "approval_pending"
                    }
                }
                _ => return Err(error),
            };
            let mut result = json!({"status": status});
            for name in ["approval_id", "expires_at"] {
                if let Some(field) = value.get(name) {
                    result[name] = field.clone();
                }
            }
            Ok(result)
        })
}

pub fn is_pending(value: &Value) -> bool {
    matches!(
        value["status"].as_str(),
        Some("approval_pending" | "still_pending")
    )
}

pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 26
        && (b'0'..=b'7').contains(&id.as_bytes()[0])
        && id
            .bytes()
            .all(|c| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&c))
}

pub fn pending_response(
    approval_id: &str,
) -> io::Result<hyper::Response<http_body_util::Full<Bytes>>> {
    if !valid_id(approval_id) {
        return Err(io::Error::other("Invalid approval ID"));
    }
    let body = json!({"error": {"type": "keyvalet_approval_pending", "approval_id": approval_id}});
    hyper::Response::builder()
        .status(hyper::StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json; charset=utf-8")
        .header("retry-after", "30")
        .header("x-keyvalet-approval", format!("pending; id={approval_id}"))
        .body(http_body_util::Full::new(Bytes::from(body.to_string())))
        .map_err(io::Error::other)
}

#[derive(Debug)]
pub struct HttpApprovalError {
    pub status: hyper::StatusCode,
    pub message: String,
}

impl std::fmt::Display for HttpApprovalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for HttpApprovalError {}

/// None means authorization only; a completed helper result must never be forwarded again.
pub fn http_response(
    decision: &Value,
) -> Result<Option<hyper::Response<Full<Bytes>>>, HttpApprovalError> {
    let bad_result = |error: io::Error| HttpApprovalError {
        status: hyper::StatusCode::BAD_GATEWAY,
        message: error.to_string(),
    };
    if is_pending(decision) {
        return pending_response(decision["approval_id"].as_str().unwrap_or_default())
            .map(Some)
            .map_err(bad_result);
    }
    let (status, error_type, message) = match decision["status"].as_str() {
        Some("ok") => {
            return decision
                .get("result")
                .filter(|value| !value.is_null())
                .map(completed_response)
                .transpose()
                .map_err(bad_result)
        }
        Some("approval_denied") => (
            hyper::StatusCode::FORBIDDEN,
            "keyvalet_approval_denied",
            "The user denied this request. Do not bypass approval or ask for a key.",
        ),
        Some("approval_cancelled") => (
            hyper::StatusCode::CONFLICT,
            "keyvalet_approval_cancelled",
            "The local approval was cancelled. A new request requires a new approval.",
        ),
        Some("approval_expired") => (
            hyper::StatusCode::GONE,
            "keyvalet_approval_expired",
            "The approval expired without a decision",
        ),
        Some("no_approver") => (
            hyper::StatusCode::SERVICE_UNAVAILABLE,
            "keyvalet_no_approver",
            "No approval channel is available",
        ),
        _ => {
            return Err(HttpApprovalError {
                status: hyper::StatusCode::BAD_GATEWAY,
                message: "Invalid helper approval result".into(),
            })
        }
    };
    Ok(Some(error_response(
        status,
        error_type,
        message,
        decision["approval_id"].as_str(),
    )))
}

pub(crate) fn error_response(
    status: hyper::StatusCode,
    error_type: &str,
    message: &str,
    id: Option<&str>,
) -> hyper::Response<Full<Bytes>> {
    let mut error = json!({"type": error_type, "message": message});
    if let Some(id) = id.filter(|id| valid_id(id)) {
        error["approval_id"] = json!(id);
    }
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        // Both official SDKs retry 409/408/5xx; a terminal local outcome must not
        // create another approval as an automatic transport retry.
        .header("x-should-retry", "false")
        .body(Full::new(Bytes::from(json!({"error":error}).to_string())))
        .unwrap()
}

fn completed_response(result: &Value) -> io::Result<hyper::Response<Full<Bytes>>> {
    use base64::engine::{general_purpose::STANDARD, Engine};
    let status = result["status"]
        .as_u64()
        .and_then(|s| u16::try_from(s).ok())
        .and_then(|s| hyper::StatusCode::from_u16(s).ok())
        .ok_or_else(|| io::Error::other("Invalid approved HTTP status"))?;
    let text = result["body"]
        .as_str()
        .ok_or_else(|| io::Error::other("Invalid approved HTTP body"))?;
    let body = if result["body_encoding"] == "base64" {
        STANDARD.decode(text).map_err(io::Error::other)?
    } else {
        text.as_bytes().to_vec()
    };
    let mut response = hyper::Response::builder().status(status);
    if let Some(headers) = result["headers"].as_object() {
        for (name, value) in headers {
            if !crate::gateway::drop_response_header(&name.to_ascii_lowercase()) {
                if let Some(value) = value.as_str() {
                    response = response.header(name, value);
                }
            }
        }
    }
    response
        .body(Full::new(Bytes::from(body)))
        .map_err(io::Error::other)
}

pub type HttpBody = http_body_util::combinators::BoxBody<Bytes, io::Error>;

pub(crate) fn boxed_response(response: hyper::Response<Full<Bytes>>) -> hyper::Response<HttpBody> {
    response.map(|body| body.map_err(|never| match never {}).boxed())
}

/// A socket that cannot keep an approval connection alive must fail before authorizing.
pub(crate) fn check_keepalive(result: io::Result<()>) -> Result<(), HttpApprovalError> {
    result.map_err(|error| HttpApprovalError {
        status: hyper::StatusCode::BAD_GATEWAY,
        message: error.to_string(),
    })
}

/// The run wrapper supplies its inherited child stderr here, rather than helper daemon stderr.
pub fn write_wait_notice(writer: &mut impl Write, label: &str) -> io::Result<()> {
    let label: String = label
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    writeln!(
        writer,
        "{}",
        kv_i18n::t(
            &format!("KeyValet: 等待 {label} 审批"),
            &format!("KeyValet: waiting for approval on {label}"),
        )
    )
}

#[cfg(unix)]
pub fn configure_keepalive(stream: &tokio::net::TcpStream) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn setsockopt(
            fd: i32,
            level: i32,
            name: i32,
            value: *const std::ffi::c_void,
            len: u32,
        ) -> i32;
    }
    #[cfg(target_os = "macos")]
    const OPTIONS: [(i32, i32, i32); 3] = [
        (0xffff, 0x0008, 1),
        (6, 0x10, TCP_KEEPALIVE_INTERVAL_S),
        (6, 0x101, TCP_KEEPALIVE_INTERVAL_S),
    ];
    #[cfg(not(target_os = "macos"))]
    const OPTIONS: [(i32, i32, i32); 3] = [
        (1, 9, 1),
        (6, 4, TCP_KEEPALIVE_INTERVAL_S),
        (6, 5, TCP_KEEPALIVE_INTERVAL_S),
    ];
    for (level, name, value) in OPTIONS {
        // SAFETY: the live socket fd and a correctly sized integer are valid for setsockopt.
        if unsafe {
            setsockopt(
                stream.as_raw_fd(),
                level,
                name,
                (&value as *const i32).cast(),
                4,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn configure_keepalive(stream: &tokio::net::TcpStream) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn setsockopt(socket: usize, level: i32, name: i32, value: *const u8, len: i32) -> i32;
        fn WSAGetLastError() -> i32;
    }
    // TCP_KEEPIDLE / TCP_KEEPINTVL are available on supported Windows 10 1709+ / Windows 11.
    for (level, name, value) in [
        (0xffff, 8, 1i32),
        (6, 3, TCP_KEEPALIVE_INTERVAL_S),
        (6, 17, TCP_KEEPALIVE_INTERVAL_S),
    ] {
        // SAFETY: the socket and four-byte integer buffer stay valid for the synchronous call.
        if unsafe {
            setsockopt(
                stream.as_raw_socket() as usize,
                level,
                name,
                (&value as *const i32).cast(),
                4,
            )
        } != 0
        {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
    }
    Ok(())
}

#[cfg(test)]
mod keepalive_tests {
    #[test]
    fn socket_errors_remain_transport_errors() {
        assert!(super::check_keepalive(Ok(())).is_ok());
        let error =
            super::check_keepalive(Err(std::io::Error::other("socket closed"))).unwrap_err();
        assert_eq!(error.status, 502);
        assert_eq!(error.to_string(), "socket closed");
    }
}
