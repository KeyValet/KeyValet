use super::{
    native::{button_reply, Button, NativeUi},
    Error, Result,
};
use serde_json::{json, Value};
use windows::core::{w, HRESULT, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    GetSysColorBrush, SetBkMode, SetTextColor, COLOR_WINDOW, HDC, TRANSPARENT,
};
use windows::Win32::UI::Controls::{
    TaskDialogIndirect, EM_LIMITTEXT, TASKDIALOGCONFIG, TASKDIALOG_BUTTON,
    TASKDIALOG_NOTIFICATIONS, TDF_ALLOW_DIALOG_CANCELLATION, TDF_CALLBACK_TIMER,
    TDF_SIZE_TO_CONTENT, TDM_CLICK_BUTTON, TDN_BUTTON_CLICKED, TDN_CREATED, TDN_TIMER,
};
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, GetClientRect, GetDlgItem, GetWindowTextW, SendMessageW, SetWindowTextW,
    CBS_DROPDOWNLIST, CB_ADDSTRING, CB_GETCURSEL, CB_SETCURSEL, ES_AUTOHSCROLL, WINDOW_EX_STYLE,
    WINDOW_STYLE, WM_CTLCOLORSTATIC, WM_SETFONT, WS_CHILD, WS_TABSTOP, WS_VISIBLE,
};

type Subclass = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM, usize, usize) -> LRESULT;
const ALLOW_BUTTON: i32 = 1001;
const DENY_BUTTON: i32 = 1002;
#[link(name = "comctl32")]
unsafe extern "system" {
    fn SetWindowSubclass(hwnd: HWND, callback: Subclass, id: usize, data: usize) -> i32;
    fn DefSubclassProc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT;
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

struct State<'a> {
    model: &'a Value,
    combo: HWND,
    editor: HWND,
    red: HWND,
    failed: bool,
    timeout: bool,
    response: Value,
}

unsafe extern "system" fn colors(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _: usize,
    data: usize,
) -> LRESULT {
    let state = &*(data as *const State<'_>);
    if msg == WM_CTLCOLORSTATIC && state.red.0 as isize == lparam.0 {
        let hdc = HDC(wparam.0 as *mut _);
        SetTextColor(hdc, COLORREF(0x000000c0));
        SetBkMode(hdc, TRANSPARENT);
        return LRESULT(GetSysColorBrush(COLOR_WINDOW).0 as isize);
    }
    DefSubclassProc(hwnd, msg, wparam, lparam)
}

unsafe fn child(
    parent: HWND,
    class: PCWSTR,
    text: &str,
    style: u32,
    frame: (i32, i32, i32, i32),
) -> Result<HWND> {
    let (x, y, width, height) = frame;
    let text = wide(text);
    let control = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        class,
        PCWSTR(text.as_ptr()),
        WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | style),
        x,
        y,
        width,
        height,
        Some(parent),
        None,
        None,
        None,
    )
    .map_err(|_| Error::UiUnavailable)?;
    let font = SendMessageW(parent, 0x0031, None, None);
    SendMessageW(
        control,
        WM_SETFONT,
        Some(WPARAM(font.0 as usize)),
        Some(LPARAM(1)),
    );
    Ok(control)
}

unsafe fn controls(hwnd: HWND, state: &mut State<'_>) -> Result<()> {
    let mut rect = RECT::default();
    GetClientRect(hwnd, &mut rect).map_err(|_| Error::UiUnavailable)?;
    let width = (rect.right - rect.left - 48).max(100);
    let mut y = (rect.bottom - 270).max(100);
    let mut red = state.model["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|row| row["red"] == true)
        .map(|row| {
            format!(
                "{}  {}",
                row["label"].as_str().unwrap_or(""),
                row["value"].as_str().unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    if state.model["title_red"] == true {
        red = format!("{}\n{red}", state.model["title"].as_str().unwrap_or(""));
    }
    if !red.is_empty() {
        let height = (red.lines().count() as i32 * 22).max(60);
        state.red = child(hwnd, w!("STATIC"), &red, 0, (24, y, width, height))?;
        if SetWindowSubclass(hwnd, colors, 1, state as *mut _ as usize) == 0 {
            return Err(Error::UiUnavailable);
        }
        y += height + 4;
    }
    if let Some(scopes) = state.model["scopes"].as_array() {
        child(
            hwnd,
            w!("STATIC"),
            state.model["scope_label"].as_str().unwrap_or(""),
            0,
            (24, y, width, 20),
        )?;
        y += 22;
        state.combo = child(
            hwnd,
            w!("COMBOBOX"),
            "",
            WS_TABSTOP.0 | CBS_DROPDOWNLIST as u32,
            (24, y, width, 240),
        )?;
        y += 34;
        for scope in scopes {
            let label = wide(scope["label"].as_str().ok_or(Error::InvalidRequest)?);
            if SendMessageW(
                state.combo,
                CB_ADDSTRING,
                None,
                Some(LPARAM(label.as_ptr() as isize)),
            )
            .0 < 0
            {
                return Err(Error::UiUnavailable);
            }
        }
        SendMessageW(
            state.combo,
            CB_SETCURSEL,
            Some(WPARAM(
                state.model["selected"].as_u64().unwrap_or(0) as usize
            )),
            None,
        );
    }
    let placeholder = state.model["reason_placeholder"]
        .as_str()
        .or_else(|| state.model["label"].as_str());
    if let Some(placeholder) = placeholder {
        child(hwnd, w!("STATIC"), placeholder, 0, (24, y, width, 22))?;
        y += 24;
        state.editor = child(
            hwnd,
            w!("EDIT"),
            "",
            WS_TABSTOP.0 | ES_AUTOHSCROLL as u32,
            (24, y, width, 26),
        )?;
        SendMessageW(state.editor, EM_LIMITTEXT, Some(WPARAM(512)), None);
    }
    if state.model["kind"] == "confirmation" {
        let button = GetDlgItem(Some(hwnd), ALLOW_BUTTON).map_err(|_| Error::UiUnavailable)?;
        let _ = EnableWindow(button, false);
    }
    Ok(())
}

unsafe fn editor_text(editor: HWND) -> String {
    if editor.0.is_null() {
        return String::new();
    }
    let mut buffer = [0u16; 514];
    let count = GetWindowTextW(editor, &mut buffer).max(0) as usize;
    String::from_utf16_lossy(&buffer[..count.min(buffer.len())])
}

unsafe extern "system" fn callback(
    hwnd: HWND,
    msg: TASKDIALOG_NOTIFICATIONS,
    wparam: WPARAM,
    _: LPARAM,
    data: isize,
) -> HRESULT {
    let state = &mut *(data as *mut State<'_>);
    if msg == TDN_CREATED && controls(hwnd, state).is_err() {
        state.failed = true;
        SendMessageW(hwnd, TDM_CLICK_BUTTON.0 as u32, Some(WPARAM(2)), None);
    }
    if msg == TDN_TIMER {
        if wparam.0 >= 120000 {
            state.timeout = true;
            SendMessageW(hwnd, TDM_CLICK_BUTTON.0 as u32, Some(WPARAM(2)), None);
        }
        if !state.combo.0.is_null() {
            let index = SendMessageW(state.combo, CB_GETCURSEL, None, None).0;
            if let Some(scope) = state.model["scopes"].as_array().and_then(|scopes| {
                usize::try_from(index)
                    .ok()
                    .and_then(|index| scopes.get(index))
            }) {
                if let (Ok(button), Some(label)) = (
                    GetDlgItem(Some(hwnd), ALLOW_BUTTON),
                    scope["allow_label"].as_str(),
                ) {
                    let text = wide(label);
                    let _ = SetWindowTextW(button, PCWSTR(text.as_ptr()));
                }
            }
        }
        if state.model["kind"] == "confirmation" {
            if let Ok(button) = GetDlgItem(Some(hwnd), ALLOW_BUTTON) {
                let _ = EnableWindow(
                    button,
                    Some(editor_text(state.editor).as_str()) == state.model["label"].as_str(),
                );
            }
        }
    }
    if msg == TDN_BUTTON_CLICKED {
        let button = match wparam.0 as i32 {
            ALLOW_BUTTON => Button::Allow,
            DENY_BUTTON => Button::Deny,
            _ => Button::Cancel,
        };
        let index = SendMessageW(state.combo, CB_GETCURSEL, None, None).0;
        state.response = button_reply(
            state.model,
            button,
            index as i64,
            &editor_text(state.editor),
            state.timeout || state.failed,
        );
    }
    HRESULT(0)
}

#[derive(Default)]
pub struct TaskDialog;
pub type NativeDialog = super::native::NativeDialog<TaskDialog>;
#[cfg(test)]
#[path = "pcp_acceptance.rs"]
mod pcp_acceptance;
impl NativeUi for TaskDialog {
    fn show(&mut self, model: &Value, screenshot: Option<&std::path::Path>) -> Result<Value> {
        if screenshot.is_some() {
            return Err(Error::UiUnavailable);
        }
        let title = wide(model["title"].as_str().ok_or(Error::InvalidRequest)?);
        let summary = wide(model["summary"].as_str().ok_or(Error::InvalidRequest)?);
        let content = model["rows"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|row| row["red"] != true)
            .map(|row| {
                format!(
                    "{}  {}",
                    row["label"].as_str().unwrap_or(""),
                    row["value"].as_str().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let content = wide(&format!("{content}\n\n\n\n\n\n\n\n\n\n\n\n"));
        let selected = model["selected"].as_u64().unwrap_or(0) as usize;
        let allow_label = model["scopes"]
            .as_array()
            .and_then(|scopes| scopes.get(selected))
            .and_then(|scope| scope["allow_label"].as_str())
            .or_else(|| model["allow_label"].as_str())
            .ok_or(Error::InvalidRequest)?;
        let allow = wide(allow_label);
        let deny = wide(model["deny_label"].as_str().ok_or(Error::InvalidRequest)?);
        let buttons = [
            TASKDIALOG_BUTTON {
                nButtonID: ALLOW_BUTTON,
                pszButtonText: PCWSTR(allow.as_ptr()),
            },
            TASKDIALOG_BUTTON {
                nButtonID: DENY_BUTTON,
                pszButtonText: PCWSTR(deny.as_ptr()),
            },
        ];
        let mut state = State {
            model,
            combo: HWND::default(),
            editor: HWND::default(),
            red: HWND::default(),
            failed: false,
            timeout: false,
            response: json!({"decision":"cancel","confirmed":false}),
        };
        let config = TASKDIALOGCONFIG {
            cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
            dwFlags: TDF_ALLOW_DIALOG_CANCELLATION | TDF_CALLBACK_TIMER | TDF_SIZE_TO_CONTENT,
            pszWindowTitle: PCWSTR(title.as_ptr()),
            pszMainInstruction: PCWSTR(summary.as_ptr()),
            pszContent: PCWSTR(content.as_ptr()),
            cButtons: 2,
            pButtons: buttons.as_ptr(),
            nDefaultButton: DENY_BUTTON,
            pfCallback: Some(callback),
            lpCallbackData: &mut state as *mut _ as isize,
            cxWidth: 430,
            ..Default::default()
        };
        unsafe {
            TaskDialogIndirect(&config, None, None, None).map_err(|_| Error::UiUnavailable)?;
        }
        if state.failed {
            return Err(Error::UiUnavailable);
        }
        Ok(state.response)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::{ApprovalView, Dialog, Selection};
    #[test]
    fn escape_close_and_timeout_leave_pending_while_explicit_denial_is_distinct() {
        let model = json!({"kind":"approval"});
        for (button, timeout, expected) in [
            (2, false, "cancel"),
            (DENY_BUTTON, false, "deny"),
            (ALLOW_BUTTON, false, "allow"),
            (DENY_BUTTON, true, "cancel"),
        ] {
            let mut state = State {
                model: &model,
                combo: HWND::default(),
                editor: HWND::default(),
                red: HWND::default(),
                failed: false,
                timeout,
                response: Value::Null,
            };
            unsafe {
                let _ = callback(
                    HWND::default(),
                    TDN_BUTTON_CLICKED,
                    WPARAM(button as usize),
                    LPARAM(0),
                    &mut state as *mut _ as isize,
                );
            }
            assert_eq!(state.response["decision"], expected);
        }
    }
    /// Run on Windows 11 in the vault owner's unlocked desktop: cargo test -p kv-agent remote_taskdialog -- --ignored --nocapture.
    #[test]
    #[ignore = "Requires an interactive Windows 11 desktop; click Deny to finish"]
    fn remote_taskdialog() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../kv-core/testdata/remote/schema_samples.json");
        let data: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mut request = data["samples"]
            .as_array()
            .unwrap()
            .iter()
            .find(|sample| sample["type"] == "ApprovalRequest")
            .unwrap()["value"]
            .clone();
        request["exp"] = json!(super::super::view::unix_seconds() + 600);
        let view = ApprovalView::new(
            &request,
            super::super::DisplayContext {
                now: super::super::view::unix_seconds(),
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
