use super::windows_logic::{WindowsProbeSignals, WindowsSignals, WindowsSnapshot};
use std::sync::{
    atomic::{AtomicBool, AtomicI8, AtomicU32, Ordering},
    Arc, Once,
};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{HANDLE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{EnumDisplayDevicesW, DISPLAY_DEVICEW, DISPLAY_DEVICE_ACTIVE};
use windows::Win32::System::Power::{
    RegisterPowerSettingNotification, UnregisterPowerSettingNotification, POWERBROADCAST_SETTING,
};
use windows::Win32::System::RemoteDesktop::*;
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::Win32::UI::WindowsAndMessaging::*;

static LOCKED: AtomicI8 = AtomicI8::new(-1);
static DISPLAY: AtomicI8 = AtomicI8::new(-1);
static SESSION: AtomicU32 = AtomicU32::new(u32::MAX);
static READY: AtomicBool = AtomicBool::new(false);
static OBSERVE: Once = Once::new();
const DISPLAY_STATE: GUID = GUID::from_u128(0x6fe69556_704a_47a0_8f24_c28d936fda47);
fn cached(value: &AtomicI8) -> Option<bool> {
    match value.load(Ordering::Acquire) {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}
unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_WTSSESSION_CHANGE && lparam.0 as u32 == SESSION.load(Ordering::Acquire) {
        match wparam.0 as u32 {
            WTS_SESSION_LOCK => LOCKED.store(1, Ordering::Release),
            WTS_SESSION_UNLOCK => LOCKED.store(0, Ordering::Release),
            WTS_SESSION_REMOTE_CONTROL
            | WTS_SESSION_LOGOFF
            | WTS_CONSOLE_DISCONNECT
            | WTS_REMOTE_DISCONNECT => LOCKED.store(-1, Ordering::Release),
            _ => {}
        }
    } else if message == WM_POWERBROADCAST
        && wparam.0 as u32 == PBT_POWERSETTINGCHANGE
        && lparam.0 != 0
    {
        let setting = unsafe { &*(lparam.0 as *const POWERBROADCAST_SETTING) };
        if setting.PowerSetting == DISPLAY_STATE && setting.DataLength == 4 {
            let value = unsafe { std::ptr::read_unaligned(setting.Data.as_ptr() as *const u32) };
            DISPLAY.store(
                match value {
                    0 => 0,
                    1 | 2 => 1,
                    _ => -1,
                },
                Ordering::Release,
            );
        }
    }
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}
fn observe(session: u32) {
    OBSERVE.call_once(|| {
        SESSION.store(session, Ordering::Release);
        let _ = std::thread::Builder::new()
            .name("kv-presence-windows".into())
            .spawn(move || {
                let name: Vec<u16> = format!("KeyValetPresence.{}", std::process::id())
                    .encode_utf16()
                    .chain(Some(0))
                    .collect();
                let class = WNDCLASSW {
                    lpfnWndProc: Some(window_proc),
                    lpszClassName: PCWSTR(name.as_ptr()),
                    ..Default::default()
                };
                if unsafe { RegisterClassW(&class) } == 0 {
                    return;
                }
                let Ok(hwnd) = (unsafe {
                    CreateWindowExW(
                        WINDOW_EX_STYLE(0),
                        PCWSTR(name.as_ptr()),
                        PCWSTR(name.as_ptr()),
                        WINDOW_STYLE(0),
                        0,
                        0,
                        0,
                        0,
                        None,
                        None,
                        None,
                        None,
                    )
                }) else {
                    return;
                };
                if unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) }.is_err()
                {
                    let _ = unsafe { DestroyWindow(hwnd) };
                    return;
                }
                let power = unsafe {
                    RegisterPowerSettingNotification(
                        HANDLE(hwnd.0),
                        &DISPLAY_STATE,
                        DEVICE_NOTIFY_WINDOW_HANDLE,
                    )
                };
                if power.is_ok() {
                    READY.store(true, Ordering::Release);
                }
                let mut message = MSG::default();
                while unsafe { GetMessageW(&mut message, None, 0, 0) }.0 > 0 {
                    unsafe {
                        let _ = TranslateMessage(&message);
                        DispatchMessageW(&message);
                    }
                }
                READY.store(false, Ordering::Release);
                unsafe {
                    let _ = WTSUnRegisterSessionNotification(hwnd);
                    if let Ok(power) = power {
                        let _ = UnregisterPowerSettingNotification(power);
                    }
                    let _ = DestroyWindow(hwnd);
                }
            });
    });
}
fn query<T: Copy>(session: u32, class: WTS_INFO_CLASS) -> Option<T> {
    let mut bytes = PWSTR::null();
    let mut size = 0;
    unsafe { WTSQuerySessionInformationW(None, session, class, &mut bytes, &mut size) }.ok()?;
    struct Buffer(PWSTR);
    impl Drop for Buffer {
        fn drop(&mut self) {
            unsafe {
                WTSFreeMemory(self.0 .0 as _);
            }
        }
    }
    let bytes = Buffer(bytes);
    if bytes.0.is_null() || size < std::mem::size_of::<T>() as u32 {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(bytes.0 .0 as *const T) })
}
fn session_state(session: u32) -> Option<WTS_CONNECTSTATE_CLASS> {
    let mut sessions = std::ptr::null_mut();
    let mut count = 0;
    unsafe { WTSEnumerateSessionsW(None, 0, 1, &mut sessions, &mut count) }.ok()?;
    struct Buffer(*mut WTS_SESSION_INFOW);
    impl Drop for Buffer {
        fn drop(&mut self) {
            unsafe {
                WTSFreeMemory(self.0 as _);
            }
        }
    }
    let sessions = Buffer(sessions);
    if sessions.0.is_null() || count > 4096 {
        return None;
    }
    unsafe { std::slice::from_raw_parts(sessions.0, count as usize) }
        .iter()
        .find(|s| s.SessionId == session)
        .map(|s| s.State)
}

pub struct SystemWindowsSignals {
    owner_sid: Vec<u8>,
}
pub type WindowsSignalSource = WindowsProbeSignals<SystemWindowsSignals>;
impl WindowsProbeSignals<SystemWindowsSignals> {
    pub fn new(owner_sid: Vec<u8>, hello: Arc<dyn Fn() -> Option<bool> + Send + Sync>) -> Self {
        if let Some(me) = crate::peer::self_identity() {
            if me.session_id != 0 {
                observe(me.session_id);
            }
        }
        Self::with_backend(SystemWindowsSignals { owner_sid }, hello)
    }
}
impl WindowsSignals for SystemWindowsSignals {
    fn snapshot(&self) -> WindowsSnapshot {
        let Some(me) = crate::peer::self_identity() else {
            return WindowsSnapshot::default();
        };
        let owner = me.session_id != 0 && crate::peer::sid_equal(&self.owner_sid, &me.sid);
        let mut snapshot = WindowsSnapshot {
            session: Some((me.session_id, owner)),
            session_state: session_state(me.session_id).map(|state| state.0),
            protocol: query::<u16>(me.session_id, WTSClientProtocolType),
            console_session: unsafe { WTSGetActiveConsoleSessionId() },
            current_tick: unsafe { GetTickCount() },
            observer_registered: READY.load(Ordering::Acquire)
                && SESSION.load(Ordering::Acquire) == me.session_id,
            ..Default::default()
        };
        if snapshot.observer_registered {
            snapshot.session_flags =
                query::<WTSINFOEXW>(me.session_id, WTSSessionInfoEx).and_then(|info| {
                    if info.Level != 1 {
                        return None;
                    }
                    Some(unsafe { info.Data.WTSInfoExLevel1 }.SessionFlags)
                });
            snapshot.lock_notification = cached(&LOCKED);
            snapshot.display_notification = cached(&DISPLAY);
        }
        let mut screensaver = windows::core::BOOL::default();
        if unsafe {
            SystemParametersInfoW(
                SPI_GETSCREENSAVERRUNNING,
                0,
                Some(&mut screensaver as *mut _ as _),
                SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
            )
        }
        .is_ok()
        {
            snapshot.screensaver_active = Some(screensaver.as_bool());
        }
        // This source must run inside the owner session, never in the LocalSystem service.
        if owner {
            let mut input = LASTINPUTINFO {
                cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
                ..Default::default()
            };
            if unsafe { GetLastInputInfo(&mut input) }.as_bool() {
                snapshot.last_input_tick = Some(input.dwTime);
            }
        }
        let mut connected = false;
        let mut complete = false;
        for i in 0..256 {
            let mut display = DISPLAY_DEVICEW {
                cb: std::mem::size_of::<DISPLAY_DEVICEW>() as u32,
                ..Default::default()
            };
            if !unsafe { EnumDisplayDevicesW(None, i, &mut display, 0) }.as_bool() {
                complete = true;
                break;
            }
            connected |= display.StateFlags.contains(DISPLAY_DEVICE_ACTIVE);
        }
        if complete {
            snapshot.display_connected = Some(connected);
        }
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::super::SignalSource;
    use super::*;

    #[test]
    fn portable_state_values_match_the_windows_sdk() {
        assert_eq!(WTSActive.0, 0);
        assert_eq!(WTS_SESSIONSTATE_LOCK, 0);
        assert_eq!(WTS_SESSIONSTATE_UNLOCK, 1);
    }
    /// Run as the unelevated vault owner in a Windows 11 console/RDP session:
    /// CARGO_TARGET_DIR=target-w1 cargo test -p kv-platform windows_presence_smoke -- --ignored
    #[test]
    #[ignore = "Requires an interactive Windows session"]
    fn windows_presence_smoke() {
        let me = crate::peer::self_identity().unwrap();
        let source = WindowsSignalSource::new(me.sid, Arc::new(|| None));
        assert_eq!(source.sample().graphical_session, Some(true));
        assert!(source.sample().idle_seconds.is_some());
    }
}
