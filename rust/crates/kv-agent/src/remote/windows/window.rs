//! Native WinUI 3 controls hosted by Microsoft's Rust projection. No key enters this process.
use super::{button_reply, read_model, Button as DialogButton, Error, Result};
use serde_json::Value;
use std::{cell::RefCell, io::Write, rc::Rc, time::Duration};
use windows::Win32::{
    Foundation::{LPARAM, LRESULT, WPARAM},
    System::Threading::GetCurrentThreadId,
    UI::{
        Input::KeyboardAndMouse::VK_ESCAPE,
        WindowsAndMessaging::{
            CallNextHookEx, SetWindowsHookExW, UnhookWindowsHookEx, HHOOK, MSG, PM_REMOVE,
            WH_GETMESSAGE, WM_KEYDOWN, WM_NULL,
        },
    },
};
use windows_reactor::*;

#[derive(Clone)]
enum Message {
    Allow,
    Deny,
    Cancel,
    Scope(Option<usize>),
    Typed(String),
    ShowReason,
    ToggleDetails,
}

thread_local! {
    static ESCAPE: RefCell<Option<LocalSender<Message>>> = const { RefCell::new(None) };
}

// Watch only removed messages on this UI thread. Escape must cancel even when the
// native scope popup or a text field has focus; it must never sign a denial.
unsafe extern "system" fn escape_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && wparam.0 == PM_REMOVE.0 as usize {
        let message = &mut *(lparam.0 as *mut MSG);
        if message.message == WM_KEYDOWN && message.wParam.0 == VK_ESCAPE.0 as usize {
            ESCAPE.with(|sender| {
                if let Some(sender) = sender.borrow().as_ref() {
                    let _ = sender.send(Message::Cancel);
                }
            });
            message.message = WM_NULL;
        }
    }
    CallNextHookEx(None, code, wparam, lparam)
}

struct EscapeMonitor(HHOOK);
impl Drop for EscapeMonitor {
    fn drop(&mut self) {
        ESCAPE.with(|sender| *sender.borrow_mut() = None);
        unsafe {
            let _ = UnhookWindowsHookEx(self.0);
        }
    }
}

type Input = (Value, Rc<RefCell<Value>>);
struct ApprovalWindow {
    model: Value,
    reply: Rc<RefCell<Value>>,
    selected: Option<usize>,
    typed: String,
    show_reason: bool,
    show_details: bool,
    _escape: EscapeMonitor,
    _timeout: ComponentTask,
}

impl Component for ApprovalWindow {
    type Input = Input;
    type Message = Message;

    fn create(input: &Input, context: &ComponentContext<Self>) -> Self {
        ESCAPE.with(|sender| *sender.borrow_mut() = Some(context.sender()));
        let hook = unsafe {
            SetWindowsHookExW(WH_GETMESSAGE, Some(escape_hook), None, GetCurrentThreadId())
                .expect("approval keyboard monitor unavailable")
        };
        let timeout = context.spawn_background(|cancel| {
            for _ in 0..1200 {
                if cancel.is_cancelled() {
                    return Message::Cancel;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Message::Cancel
        });
        Self {
            model: input.0.clone(),
            reply: Rc::clone(&input.1),
            selected: input.0["selected"]
                .as_u64()
                .and_then(|n| usize::try_from(n).ok()),
            typed: String::new(),
            show_reason: false,
            show_details: false,
            _escape: EscapeMonitor(hook),
            _timeout: timeout,
        }
    }

    fn update(&mut self, message: Message, context: &ComponentContext<Self>) {
        match message {
            Message::Scope(selected) => self.selected = selected,
            Message::Typed(text) => self.typed = text,
            Message::ShowReason => self.show_reason = true,
            Message::ToggleDetails => self.show_details = !self.show_details,
            Message::Allow | Message::Deny | Message::Cancel => {
                let button = match message {
                    Message::Allow => DialogButton::Allow,
                    Message::Deny => DialogButton::Deny,
                    _ => DialogButton::Cancel,
                };
                if context.window().request_close() {
                    *self.reply.borrow_mut() = button_reply(
                        &self.model,
                        button,
                        self.selected.map(|n| n as i64).unwrap_or(-1),
                        &self.typed,
                        false,
                    );
                }
            }
        }
    }

    fn view(&self, _input: &Input, context: &mut ViewContext<Self>) -> View {
        let model = &self.model;
        let rows = model["rows"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        let primary_count = rows
            .iter()
            .filter(|row| row["detail"] != true || row["red"] == true)
            .count();
        let initial_height = if model["kind"] == "approval" {
            294.0 + primary_count as f64 * 30.0
        } else {
            240.0 + primary_count as f64 * 30.0
        };
        context.window_title("KeyValet");
        context.window_visuals(
            WindowVisuals::new()
                .client_size(460.0, initial_height.min(620.0))
                .constraints(WindowConstraints {
                    min_width: Some(420.0),
                    min_height: Some(260.0),
                    ..Default::default()
                })
                .backdrop(WindowBackdrop::Mica),
        );
        let primary = rows
            .iter()
            .filter(|row| row["detail"] != true || row["red"] == true);
        let details = rows
            .iter()
            .filter(|row| row["detail"] == true && row["red"] != true);
        let mut body = vec![header(model), request_summary(model)];
        if rows
            .iter()
            .any(|row| row["detail"] != true || row["red"] == true)
        {
            body.push(row_card(primary));
        }
        if let Some(scopes) = model["scopes"]
            .as_array()
            .filter(|scopes| !scopes.is_empty())
        {
            let choice: View = if scopes.len() == 1 {
                text(string(&scopes[0], "label"), 13.0).into()
            } else {
                ComboBox::new()
                    .items_source(scopes.iter().map(|scope| string(scope, "label")))
                    .selected_index(self.selected)
                    .horizontal_alignment(HorizontalAlignment::Right)
                    .on_selection_changed(context.callback(Message::Scope))
                    .into()
            };
            body.push(
                Grid::new()
                    .columns([GridLength::Auto, GridLength::Star(1.0)])
                    .column_spacing(12.0)
                    .children((
                        text(string(model, "scope_label"), 12.0)
                            .opacity(0.7)
                            .vertical_alignment(VerticalAlignment::Center),
                        Border::new()
                            .grid_column(1)
                            .horizontal_alignment(HorizontalAlignment::Right)
                            .content(choice),
                    )),
            );
        }
        let has_details = rows
            .iter()
            .any(|row| row["detail"] == true && row["red"] != true);
        let mut actions = Vec::new();
        if has_details {
            actions.push(
                Button::new()
                    .style(ButtonStyle::TextLink)
                    .horizontal_alignment(HorizontalAlignment::Left)
                    .on_click(context.message(Message::ToggleDetails))
                    .content(format!(
                        "{} {}",
                        if self.show_details { "⌄" } else { "›" },
                        string(model, "details_label")
                    )),
            );
        }
        if model["reason_placeholder"].is_string() && !self.show_reason {
            actions.push(
                Button::new()
                    .grid_column(1)
                    .style(ButtonStyle::TextLink)
                    .horizontal_alignment(HorizontalAlignment::Right)
                    .on_click(context.message(Message::ShowReason))
                    .content(string(model, "reason_label")),
            );
        }
        if !actions.is_empty() {
            body.push(
                Grid::new()
                    .columns([GridLength::Star(1.0), GridLength::Auto])
                    .keyed_children(
                        actions
                            .into_iter()
                            .enumerate()
                            .map(|(index, view)| KeyedView::new(index.to_string(), view)),
                    ),
            );
        }
        if has_details && self.show_details {
            body.push(row_card(details));
        }
        if model["kind"] == "confirmation" || self.show_reason {
            let placeholder = model["reason_placeholder"]
                .as_str()
                .or_else(|| model["label"].as_str())
                .unwrap_or("");
            body.push(
                TextBox::new()
                    .text(&self.typed)
                    .placeholder_text(placeholder)
                    .accepts_return(false)
                    .on_text_changed(context.callback(Message::Typed))
                    .into(),
            );
        }
        let allow = model["scopes"]
            .as_array()
            .and_then(|scopes| self.selected.and_then(|n| scopes.get(n)))
            .and_then(|scope| scope["allow_label"].as_str())
            .or_else(|| model["allow_label"].as_str())
            .unwrap_or("");
        let can_allow = (model["kind"] != "confirmation"
            || model["label"].as_str() == Some(self.typed.as_str()))
            && (model["kind"] != "approval" || self.selected.is_some());
        let footer = Border::new()
            .grid_row(1)
            .padding(Thickness::xy(18.0, 12.0))
            .border_thickness(Thickness::new(0.0, 1.0, 0.0, 0.0))
            .border_brush(ThemeBrush::CardStroke)
            .content(
                StackPanel::new()
                    .orientation(Orientation::Horizontal)
                    .spacing(8.0)
                    .horizontal_alignment(HorizontalAlignment::Right)
                    .children((
                        Button::new()
                            .on_click(context.message(Message::Deny))
                            .content(string(model, "deny_label")),
                        Button::new()
                            .style(ButtonStyle::Accent)
                            .is_enabled(can_allow)
                            .on_click(context.message(Message::Allow))
                            .content(allow),
                    )),
            );
        Grid::new()
            .rows([GridLength::Star(1.0), GridLength::Auto])
            .children((
                ScrollViewer::new().content(Border::new().padding(18.0).content(stack(body, 10.0))),
                footer,
            ))
    }
}

fn string<'a>(model: &'a Value, key: &str) -> &'a str {
    model[key].as_str().unwrap_or("")
}
fn text(value: &str, size: f64) -> TextBlock {
    TextBlock::new()
        .text(value)
        .font_size(size)
        .text_wrapping(TextWrapping::Wrap)
        .is_text_selection_enabled(true)
}
fn stack(views: Vec<View>, spacing: f64) -> View {
    StackPanel::new().spacing(spacing).keyed_children(
        views
            .into_iter()
            .enumerate()
            .map(|(index, view)| KeyedView::new(index.to_string(), view)),
    )
}
fn row_card<'a>(rows: impl Iterator<Item = &'a Value>) -> View {
    let views = rows
        .map(|row| {
            let foreground = if row["red"] == true {
                ThemeBrush::SystemCritical
            } else {
                ThemeBrush::PrimaryText
            };
            Grid::new()
                .columns([GridLength::Pixel(84.0), GridLength::Star(1.0)])
                .column_spacing(10.0)
                .children((
                    text(string(row, "label"), 12.0).opacity(0.7),
                    text(string(row, "value"), 13.0)
                        .grid_column(1)
                        .opacity(if row["secondary"] == true && row["red"] != true {
                            0.7
                        } else {
                            1.0
                        })
                        .foreground(foreground),
                ))
        })
        .collect();
    Border::new()
        .padding(10.0)
        .corner_radius(7.0)
        .background(ThemeBrush::CardBackground)
        .border_thickness(1.0)
        .border_brush(ThemeBrush::CardStroke)
        .content(stack(views, 8.0))
}
fn header(model: &Value) -> View {
    let mut labels = vec![text(
        model["heading"].as_str().unwrap_or(string(model, "title")),
        17.0,
    )
    .font_weight(FontWeight::SEMI_BOLD)
    .foreground(if model["title_red"] == true {
        ThemeBrush::SystemCritical
    } else {
        ThemeBrush::PrimaryText
    })
    .into()];
    if model["heading"].is_string() {
        labels.push(
            text(
                model["subtitle"].as_str().unwrap_or(string(model, "title")),
                12.0,
            )
            .opacity(0.7)
            .into(),
        );
    }
    Grid::new()
        .columns([GridLength::Auto, GridLength::Star(1.0)])
        .column_spacing(10.0)
        .children((
            Border::new()
                .width(32.0)
                .height(32.0)
                .corner_radius(8.0)
                .background(ThemeBrush::Accent)
                .content(
                    text("KV", 13.0)
                        .font_weight(FontWeight::SEMI_BOLD)
                        .foreground(Color::rgb(255, 255, 255))
                        .horizontal_alignment(HorizontalAlignment::Center)
                        .vertical_alignment(VerticalAlignment::Center),
                ),
            Border::new().grid_column(1).content(stack(labels, 3.0)),
        ))
}
fn request_summary(model: &Value) -> View {
    let target = model["request_target"]
        .as_str()
        .unwrap_or(string(model, "summary"));
    let summary = text(
        target,
        if model["kind"] == "pairing" {
            28.0
        } else {
            14.0
        },
    );
    let mut content = vec![summary.font_weight(FontWeight::MEDIUM).into()];
    if model["request_target"].is_string() && target != string(model, "summary") {
        content.push(text(string(model, "summary"), 12.0).opacity(0.7).into());
    }
    Border::new()
        .padding(10.0)
        .corner_radius(7.0)
        .background(ThemeBrush::CardBackground)
        .content(stack(content, 5.0))
}

pub(super) fn run() -> Result<()> {
    let model = read_model(&mut std::io::stdin().lock())?;
    let reply = Rc::new(RefCell::new(button_reply(
        &model,
        DialogButton::Cancel,
        0,
        "",
        false,
    )));
    App::run_component::<ApprovalWindow>((model, Rc::clone(&reply)))
        .map_err(|_| Error::UiUnavailable)?;
    serde_json::to_writer(std::io::stdout().lock(), &*reply.borrow())
        .map_err(|_| Error::UiUnavailable)?;
    std::io::stdout().flush().map_err(|_| Error::UiUnavailable)
}
