//! Bounded wire framing; real socket authentication remains in the system runner.

use super::output;
use super::relay::{self, RelayUrl};
use super::{Error, Result};
use kv_core::remote::ipc::{Request, Response};
#[cfg(any(unix, test))]
use std::io::BufRead;
use std::io::{Read, Write};

pub(super) const FRAME_LIMIT: u64 = 1024 * 1024;

pub(super) fn unavailable(error: std::io::Error) -> Error {
    let code = if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        "timeout"
    } else {
        "ipc_unavailable"
    };
    Error {
        code: code.into(),
        message: output::error_message(code),
        completed_devices: Vec::new(),
    }
}

#[cfg(any(unix, test))]
pub(super) fn unavailable_at(request: &Request, stage: &str, error: std::io::Error) -> Error {
    let kind = error.kind();
    let mut result = unavailable(error);
    // Only fixed transport metadata reaches the error. Pair URI and request fields stay private.
    result.message = format!(
        "{} ({} / {stage} / {kind:?})",
        result.message,
        request.op.as_str()
    );
    result
}

/// Bounded response-only framing shared with the in-process fake socket harness.
#[cfg(any(unix, test))]
pub(super) fn exchange_stream(
    stream: &mut (impl Read + Write),
    request: &Request,
) -> Result<Response> {
    let bytes = encode_request(request)?;
    stream
        .write_all(&bytes)
        .map_err(|error| unavailable_at(request, "write_request", error))?;
    let mut reply = Vec::new();
    std::io::BufReader::new(stream)
        .take(FRAME_LIMIT + 1)
        .read_until(b'\n', &mut reply)
        .map_err(|error| unavailable_at(request, "read_response", error))?;
    if reply.is_empty() {
        return Err(unavailable_at(
            request,
            "read_response",
            std::io::ErrorKind::UnexpectedEof.into(),
        ));
    }
    decode_response(&reply)
}

pub(super) fn decode_response(reply: &[u8]) -> Result<Response> {
    if reply.is_empty() {
        return Err(unavailable(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof,
        )));
    }
    if reply.len() as u64 > FRAME_LIMIT || reply.last() != Some(&b'\n') {
        return Err(Error::protocol());
    }
    kv_core::remote::canonical::from_json(reply).map_err(|_| Error::protocol())
}

pub(super) fn http_health(
    stream: &mut (impl Read + Write),
    url: &RelayUrl,
) -> Result<relay::Health> {
    let path = if url.path.is_empty() {
        "/v1/health".into()
    } else {
        format!("/{}/v1/health", url.path)
    };
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        url.authority
    )
    .map_err(|_| relay::health_error())?;
    let mut bytes = Vec::new();
    stream
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| relay::health_error())?;
    if bytes.len() > 64 * 1024 {
        return Err(relay::health_error());
    }
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(relay::health_error)?;
    let headers = std::str::from_utf8(&bytes[..split]).map_err(|_| relay::health_error())?;
    if headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        != Some("200")
    {
        return Err(Error::new(
            "relay_unreachable",
            "relay 健康检查失败",
            "The relay health check failed",
        ));
    }
    let body = &bytes[split + 4..];
    if headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    }) {
        relay::parse_health(&decode_chunks(body)?)
    } else {
        relay::parse_health(body)
    }
}

fn decode_chunks(mut bytes: &[u8]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let end = bytes
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(relay::health_error)?;
        let size = std::str::from_utf8(&bytes[..end]).map_err(|_| relay::health_error())?;
        let size = size.split_once(';').map_or(size, |(size, _)| size);
        let size = usize::from_str_radix(size, 16).map_err(|_| relay::health_error())?;
        bytes = &bytes[end + 2..];
        if size == 0 {
            // Consume the trailer terminator too; truncated zero chunks are invalid.
            loop {
                let end = bytes
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .ok_or_else(relay::health_error)?;
                let trailer = &bytes[..end];
                bytes = &bytes[end + 2..];
                if trailer.is_empty() {
                    return if bytes.is_empty() {
                        Ok(body)
                    } else {
                        Err(relay::health_error())
                    };
                }
                if !trailer.contains(&b':') {
                    return Err(relay::health_error());
                }
            }
        }
        if size > bytes.len().saturating_sub(2) || bytes.get(size..size + 2) != Some(b"\r\n") {
            return Err(relay::health_error());
        }
        body.extend_from_slice(&bytes[..size]);
        bytes = &bytes[size + 2..];
    }
}

pub(super) fn encode_request(request: &Request) -> Result<Vec<u8>> {
    // Request contains only strings and JSON values; serialization cannot fail.
    let mut bytes = serde_json::to_vec(request).expect("Request has only JSON fields");
    if bytes.len() as u64 >= FRAME_LIMIT {
        return Err(Error::argument(
            "IPC 请求过大",
            "The IPC request is too large",
        ));
    }
    bytes.push(b'\n');
    Ok(bytes)
}
