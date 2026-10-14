//! Each approval uses a fresh WinUI process, separate from the Hello/key apartment.
use super::{
    native::{button_reply, Button, NativeUi},
    Error, Result,
};
use serde_json::Value;
use std::{
    io::{Read, Write},
    os::windows::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

mod window;
const MAX_MODEL: u64 = 131072;
const MAX_REPLY: u64 = 8192;

#[derive(Default)]
pub struct WinUi;
pub type NativeDialog = super::native::NativeDialog<WinUi>;

struct WindowProcess(Child);
impl Drop for WindowProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl NativeUi for WinUi {
    fn show(&mut self, model: &Value, screenshot: Option<&Path>) -> Result<Value> {
        if screenshot.is_some() {
            return Err(Error::UiUnavailable);
        }
        let input = serde_json::to_vec(model).map_err(|_| Error::InvalidRequest)?;
        if input.len() as u64 > MAX_MODEL {
            return Err(Error::InvalidRequest);
        }
        let executable = std::env::current_exe().map_err(|_| Error::UiUnavailable)?;
        // GUI-only library fixtures run from target/debug/deps. Production launches
        // the same already-trusted agent, rather than a separately trusted UI program.
        #[cfg(test)]
        let executable = if executable.parent().and_then(Path::file_name)
            == Some(std::ffi::OsStr::new("deps"))
        {
            executable
                .parent()
                .and_then(Path::parent)
                .ok_or(Error::UiUnavailable)?
                .join("kv-agent.exe")
        } else {
            executable
        };
        let mut child = WindowProcess(
            Command::new(&executable)
                .arg("--remote-window")
                .current_dir(executable.parent().ok_or(Error::UiUnavailable)?)
                .creation_flags(0x08000000) // CREATE_NO_WINDOW hides only the console.
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| Error::UiUnavailable)?,
        );
        child
            .0
            .stdin
            .take()
            .ok_or(Error::UiUnavailable)?
            .write_all(&input)
            .map_err(|_| Error::UiUnavailable)?;
        let stdout = child.0.stdout.take().ok_or(Error::UiUnavailable)?;
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .take(MAX_REPLY + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let deadline = Instant::now() + Duration::from_secs(125);
        loop {
            if let Some(status) = child.0.try_wait().map_err(|_| Error::UiUnavailable)? {
                if !status.success() {
                    return Err(Error::UiUnavailable);
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err(Error::UiUnavailable);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let bytes = reader
            .join()
            .map_err(|_| Error::UiUnavailable)?
            .map_err(|_| Error::UiUnavailable)?;
        if bytes.len() as u64 > MAX_REPLY {
            return Err(Error::InvalidResponse);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)
    }
}

fn read_model(reader: &mut impl Read) -> Result<Value> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_MODEL + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidRequest)?;
    if bytes.len() as u64 > MAX_MODEL {
        return Err(Error::InvalidRequest);
    }
    let model: Value = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidRequest)?;
    let valid_kind = matches!(
        model["kind"].as_str(),
        Some("approval" | "pairing" | "confirmation" | "global_grant")
    );
    if !valid_kind
        || !model["title"].is_string()
        || !model["summary"].is_string()
        || !model["deny_label"].is_string()
    {
        return Err(Error::InvalidRequest);
    }
    if model["kind"] == "approval" {
        let scopes = model["scopes"]
            .as_array()
            .filter(|scopes| !scopes.is_empty() && scopes.len() <= 8)
            .ok_or(Error::InvalidRequest)?;
        let selected = model["selected"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or(Error::InvalidRequest)?;
        if selected >= scopes.len()
            || scopes
                .iter()
                .any(|scope| !scope["label"].is_string() || !scope["allow_label"].is_string())
        {
            return Err(Error::InvalidRequest);
        }
    } else if !model["allow_label"].is_string() {
        return Err(Error::InvalidRequest);
    }
    if model["kind"] == "confirmation" && model["label"].as_str().is_none_or(str::is_empty) {
        return Err(Error::InvalidRequest);
    }
    if let Some(rows) = model.get("rows") {
        let rows = rows
            .as_array()
            .filter(|rows| rows.len() <= 64)
            .ok_or(Error::InvalidRequest)?;
        if rows
            .iter()
            .any(|row| !row["label"].is_string() || !row["value"].is_string())
        {
            return Err(Error::InvalidRequest);
        }
    }
    Ok(model)
}

pub fn run_window() -> Result<()> {
    window::run()
}

#[cfg(test)]
#[path = "pcp_acceptance.rs"]
mod pcp_acceptance;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::{ApprovalView, Dialog, Selection};
    use serde_json::json;
    #[test]
    fn malformed_and_oversized_window_models_never_initialize_winui() {
        for input in [
            b"{}".to_vec(),
            b"FORBIDDEN".to_vec(),
            vec![b'x'; MAX_MODEL as usize + 1],
        ] {
            assert!(read_model(&mut input.as_slice()).is_err());
        }
        let mut model = json!({"kind":"approval","title":"test","summary":"test","deny_label":"Deny",
            "scopes":[{"label":"This request","allow_label":"Allow"}],"selected":1});
        assert!(read_model(&mut serde_json::to_vec(&model).unwrap().as_slice()).is_err());
        model["selected"] = json!(0);
        assert!(read_model(&mut serde_json::to_vec(&model).unwrap().as_slice()).is_ok());
    }
    #[test]
    fn escape_close_and_timeout_leave_pending_while_explicit_denial_is_distinct() {
        let model = json!({"kind":"approval"});
        for (button, timeout, expected) in [
            (Button::Cancel, false, "cancel"),
            (Button::Deny, false, "deny"),
            (Button::Allow, false, "allow"),
            (Button::Deny, true, "cancel"),
        ] {
            assert_eq!(
                button_reply(&model, button, 0, "", timeout)["decision"],
                expected
            );
        }
    }
    /// Run in an unlocked Windows desktop: cargo test -p kv-agent remote_winui -- --ignored --nocapture.
    #[test]
    #[ignore = "Requires an interactive Windows desktop; click Deny or close the native WinUI window"]
    fn remote_winui() {
        let data: Value = serde_json::from_str(
            &std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../kv-core/testdata/remote/schema_samples.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let mut request = data["samples"]
            .as_array()
            .unwrap()
            .iter()
            .find(|sample| sample["type"] == "ApprovalRequest")
            .unwrap()["value"]
            .clone();
        let now = super::super::view::unix_seconds();
        request["exp"] = json!(now + 600);
        let view = ApprovalView::new(
            &request,
            super::super::DisplayContext {
                now,
                ..Default::default()
            },
            super::super::Platform::Windows,
        )
        .unwrap();
        assert!(matches!(
            NativeDialog::default().approval(&view).unwrap(),
            Selection::Deny { .. } | Selection::Cancel
        ));
    }
}
