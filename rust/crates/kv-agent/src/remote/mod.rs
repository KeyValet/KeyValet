//! Desktop presentation and unsigned helper workflows. Hardware providers remain in W1.
use serde_json::{json, Value};
use std::fmt;

pub mod agent;
pub mod flows;
pub mod native;
pub mod queue;
pub mod stdio;
pub mod view;
#[cfg(windows)]
pub mod windows;

pub use flows::{ApprovalFlow, Helper, PairingFlow};
pub use view::{ApprovalView, DisplayContext, Platform};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidRequest,
    InvalidScope,
    Expired,
    MissingState,
    Cancelled,
    ConfirmationRequired,
    KeyUnavailable,
    HelperUnavailable,
    InvalidResponse,
    UiUnavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "invalid_remote_request",
            Self::InvalidScope => "invalid_remote_scope",
            Self::Expired => "remote_request_expired",
            Self::MissingState => "remote_setting_unavailable",
            Self::Cancelled => "remote_action_cancelled",
            Self::ConfirmationRequired => "secondary_confirmation_required",
            Self::KeyUnavailable => "approval_key_unavailable",
            Self::HelperUnavailable => "remote_helper_unavailable",
            Self::InvalidResponse => "invalid_remote_response",
            Self::UiUnavailable => "remote_ui_unavailable",
        })
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Quick,
    Strong,
}
impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Strong => "strong",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "quick" => Ok(Self::Quick),
            "strong" => Ok(Self::Strong),
            _ => Err(Error::InvalidRequest),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    Allow { scope: String },
    Deny { reason: Option<String> },
    Cancel,
}

pub trait Dialog {
    fn approval(&mut self, view: &ApprovalView) -> Result<Selection>;
    fn pairing(&mut self, view: &view::PairingView) -> Result<bool>;
    fn confirm_label(&mut self, view: &view::ConfirmationView) -> Result<Option<String>>;
    fn confirm_global(&mut self, _view: &view::GlobalGrantView) -> Result<bool> {
        Err(Error::UiUnavailable)
    }
}

pub(crate) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidRequest)
}

pub(crate) fn display_text(value: &str) -> Result<String> {
    // CONTRACT: §6.3 / §9.2: do not let control characters impersonate another UI field.
    if value.len() > 8192
        || value.chars().any(|c| {
            (c.is_control() && c != '\n' && c != '\t')
                || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
    {
        return Err(Error::InvalidRequest);
    }
    Ok(value.to_owned())
}

pub(crate) fn request(op: kv_ipc::remote::Op, params: Value) -> kv_ipc::remote::Request {
    kv_ipc::remote::Request {
        op,
        params,
        extra: Default::default(),
    }
}

pub fn handle_dialog(input: &Value, dialog: &mut dyn Dialog, platform: Platform) -> Result<Value> {
    match text(input, "op")? {
        "remote_approval" => {
            let context = DisplayContext::from_json(&input["context"])?;
            let view = ApprovalView::new(&input["request"], context, platform)?;
            let selection = dialog.approval(&view)?;
            let now = view::unix_seconds();
            let params = ApprovalFlow::decision_params(&view, selection, now)?;
            Ok(json!({"ok":true,"params":params}))
        }
        "remote_pair" => {
            let view = view::PairingView::new(&input["peer"], text(input, "sas")?, platform)?;
            Ok(json!({"ok":true,"confirmed":dialog.pairing(&view)?}))
        }
        "remote_confirm_label" => {
            let view = if input["action"] == "revoke_device" {
                view::ConfirmationView::revocation(text(input, "label")?)?
            } else {
                view::ConfirmationView::new(
                    text(input, "label")?,
                    platform,
                    input["standing"] == true,
                )?
            };
            let typed = dialog.confirm_label(&view)?;
            Ok(json!({"ok":true,"confirmed":typed.as_deref()==Some(view.label.as_str())}))
        }
        "remote_confirm_global" => Ok(
            json!({"ok":true,"confirmed":dialog.confirm_global(&view::GlobalGrantView::new(platform))?}),
        ),
        _ => Err(Error::InvalidRequest),
    }
}

#[cfg(test)]
mod tests;
