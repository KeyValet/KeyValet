use super::{
    view::{ConfirmationView, GlobalGrantView, PairingView},
    ApprovalView, Dialog, Error, Result, Selection,
};
use serde_json::{json, Value};
use std::path::Path;

pub trait NativeUi {
    fn show(&mut self, payload: &Value, screenshot: Option<&Path>) -> Result<Value>;
}

pub trait RawDialog {
    fn call(&self, input: &[u8], output: &mut [u8], length: &mut usize, preview: &[u8]) -> i32;
}

pub trait PreviewDialog: Dialog {
    fn preview(&mut self, view: &ApprovalView, screenshot: &Path) -> Result<()>;
    fn preview_pairing(&mut self, view: &PairingView, screenshot: &Path) -> Result<()>;
}

#[derive(Default)]
pub struct NativeBridge<B>(pub B);
impl<B: RawDialog> NativeUi for NativeBridge<B> {
    fn show(&mut self, payload: &Value, screenshot: Option<&Path>) -> Result<Value> {
        let input = serde_json::to_vec(payload).map_err(|_| Error::InvalidRequest)?;
        let path = screenshot
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut output = [0u8; 8192];
        let mut length = output.len();
        let code = self
            .0
            .call(&input, &mut output, &mut length, path.as_bytes());
        if code != 0 || length > output.len() {
            return Err(Error::UiUnavailable);
        }
        serde_json::from_slice(&output[..length]).map_err(|_| Error::InvalidResponse)
    }
}

#[derive(Default)]
pub struct NativeDialog<B> {
    pub(super) backend: B,
}
impl<B> NativeDialog<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn selection(view: &ApprovalView, reply: &Value) -> Result<Selection> {
        match reply["decision"].as_str() {
            Some("allow") => {
                let index = reply["selected"]
                    .as_u64()
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or(Error::InvalidResponse)?;
                let scope = view.scopes.get(index).ok_or(Error::InvalidResponse)?;
                Ok(Selection::Allow {
                    scope: scope.value.clone(),
                })
            }
            Some("deny") => Ok(Selection::Deny {
                reason: reply
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            }),
            Some("cancel") => Ok(Selection::Cancel),
            _ => Err(Error::InvalidResponse),
        }
    }
}
impl<B: NativeUi> NativeDialog<B> {
    /// A GUI-only preview always cancels and never signs or submits an approval.
    pub fn preview(&mut self, view: &ApprovalView, screenshot: &Path) -> Result<()> {
        self.backend.show(&view.payload(), Some(screenshot))?;
        Ok(())
    }
    pub fn preview_pairing(&mut self, view: &PairingView, screenshot: &Path) -> Result<()> {
        self.backend.show(&view.payload(), Some(screenshot))?;
        Ok(())
    }
}
impl<B: NativeUi> PreviewDialog for NativeDialog<B> {
    fn preview(&mut self, view: &ApprovalView, screenshot: &Path) -> Result<()> {
        NativeDialog::preview(self, view, screenshot)
    }
    fn preview_pairing(&mut self, view: &PairingView, screenshot: &Path) -> Result<()> {
        NativeDialog::preview_pairing(self, view, screenshot)
    }
}
impl<B: NativeUi> Dialog for NativeDialog<B> {
    fn confirm_global(&mut self, view: &GlobalGrantView) -> Result<bool> {
        confirmed(&self.backend.show(&view.payload(), None)?)
    }
    fn approval(&mut self, view: &ApprovalView) -> Result<Selection> {
        Self::selection(view, &self.backend.show(&view.payload(), None)?)
    }
    fn pairing(&mut self, view: &PairingView) -> Result<bool> {
        confirmed(&self.backend.show(&view.payload(), None)?)
    }
    fn confirm_label(&mut self, view: &ConfirmationView) -> Result<Option<String>> {
        let reply = self.backend.show(&view.payload(), None)?;
        if confirmed(&reply)? {
            Ok(Some(
                reply["text"]
                    .as_str()
                    .ok_or(Error::InvalidResponse)?
                    .to_owned(),
            ))
        } else {
            Ok(None)
        }
    }
}

fn confirmed(reply: &Value) -> Result<bool> {
    reply["confirmed"].as_bool().ok_or(Error::InvalidResponse)
}

#[derive(Clone, Copy)]
pub enum Button {
    Allow,
    Deny,
    Cancel,
}

pub fn button_reply(
    model: &Value,
    button: Button,
    selected: i64,
    typed: &str,
    unavailable: bool,
) -> Value {
    // CONTRACT: §6.9 / D10: failed UI, timeout and closing preserve pending state.
    let approved = matches!(button, Button::Allow)
        && !unavailable
        && (model["kind"] != "confirmation" || model["label"].as_str() == Some(typed));
    if model["kind"] == "approval" {
        json!({"decision":if approved {"allow"} else if matches!(button, Button::Deny) && !unavailable {"deny"} else {"cancel"},"selected":selected,"reason":typed})
    } else {
        json!({"confirmed":approved,"text":typed})
    }
}
