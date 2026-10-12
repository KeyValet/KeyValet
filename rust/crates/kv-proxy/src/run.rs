//! Child-process adapter for the `keyvalet run` CLI entry point.

use crate::approval::write_wait_notice;
use std::io;
use std::process::ExitStatus;
use tokio::process::Command;
use tokio::sync::mpsc;

pub fn session_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(io::Error::other)?;
    Ok(format!(
        "run-{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

pub fn sdk_key_env(template: Option<&str>) -> Option<&'static str> {
    match template {
        Some("openai") => Some("OPENAI_API_KEY"),
        Some("anthropic") => Some("ANTHROPIC_API_KEY"),
        _ => None,
    }
}

/// Keep the child's normal stderr and add one line when its proxy starts waiting for approval.
/// The wrapper and child inherit the same stderr descriptor; no daemon logs are forwarded.
pub async fn run_with_approval_notices(
    command: &mut Command,
    mut notices: mpsc::UnboundedReceiver<String>,
) -> io::Result<ExitStatus> {
    let mut child = command.kill_on_drop(true).spawn()?;
    let exited = child.wait();
    tokio::pin!(exited);
    loop {
        tokio::select! {
            result = &mut exited => return result,
            label = notices.recv() => match label {
                Some(label) => write_wait_notice(&mut io::stderr().lock(), &label)?,
                None => return exited.await,
            }
        }
    }
}
