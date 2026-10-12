use super::{unavailable_signals, PresenceSignals, SignalSource};
use core_foundation_sys::{
    base::{CFGetTypeID, CFRelease, CFTypeRef},
    dictionary::{CFDictionaryGetValue, CFDictionaryRef},
    notification_center::*,
    number::{CFBooleanGetTypeID, CFBooleanGetValue},
    runloop::CFRunLoopRun,
    string::{kCFStringEncodingUTF8, CFStringCreateWithBytes, CFStringGetCString, CFStringRef},
};
use std::ffi::c_void;
use std::sync::{
    atomic::{AtomicI8, Ordering},
    Arc, Once,
};

#[link(name = "SystemConfiguration", kind = "framework")]
extern "C" {
    fn SCDynamicStoreCopyConsoleUser(
        store: *const c_void,
        uid: *mut u32,
        gid: *mut u32,
    ) -> CFStringRef;
}
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    fn CGEventSourceSecondsSinceLastEventType(state: i32, event: u32) -> f64;
    fn CGGetActiveDisplayList(max: u32, displays: *mut u32, count: *mut u32) -> i32;
    fn CGDisplayIsAsleep(display: u32) -> u32;
}

static LOCKED: AtomicI8 = AtomicI8::new(-1);
static SAVER: AtomicI8 = AtomicI8::new(-1);
static OBSERVE: Once = Once::new();

struct Owned(CFTypeRef);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CFRelease(self.0);
            }
        }
    }
}

fn cf_string(text: &str) -> Owned {
    Owned(unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            text.as_ptr(),
            text.len() as isize,
            kCFStringEncodingUTF8,
            0,
        )
    } as CFTypeRef)
}
fn string(value: CFStringRef) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let mut bytes = [0i8; 256];
    if unsafe {
        CFStringGetCString(
            value,
            bytes.as_mut_ptr(),
            bytes.len() as isize,
            kCFStringEncodingUTF8,
        )
    } == 0
    {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(bytes.as_ptr()) }
        .to_str()
        .ok()
        .map(str::to_owned)
}
fn boolean(dict: CFDictionaryRef, key: &str) -> Option<bool> {
    let key = cf_string(key);
    boolean_value(dict, key.0)
}
fn boolean_value(dict: CFDictionaryRef, key: CFTypeRef) -> Option<bool> {
    if dict.is_null() {
        return None;
    }
    if key.is_null() {
        return None;
    }
    let value = unsafe { CFDictionaryGetValue(dict, key) };
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFBooleanGetTypeID() } {
        return None;
    }
    Some(unsafe { CFBooleanGetValue(value as _) })
}
fn cached(value: &AtomicI8) -> Option<bool> {
    match value.load(Ordering::Acquire) {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}
extern "C" fn notification(
    _: CFNotificationCenterRef,
    _: *mut c_void,
    name: CFStringRef,
    _: *const c_void,
    _: CFDictionaryRef,
) {
    notification_name(name, &LOCKED, &SAVER);
}
fn notification_name(name: CFStringRef, locked: &AtomicI8, saver: &AtomicI8) {
    match string(name).as_deref() {
        Some("com.apple.screenIsLocked") => locked.store(1, Ordering::Release),
        Some("com.apple.screenIsUnlocked") => locked.store(0, Ordering::Release),
        Some("com.apple.screensaver.didstart") => saver.store(1, Ordering::Release),
        Some("com.apple.screensaver.didstop") => saver.store(0, Ordering::Release),
        _ => {}
    }
}
fn register_notifications(
    center: CFNotificationCenterRef,
    mut name: impl FnMut(&str) -> Owned,
    mut add: impl FnMut(CFNotificationCenterRef, CFStringRef),
) {
    if center.is_null() {
        return;
    }
    for text in [
        "com.apple.screenIsLocked",
        "com.apple.screenIsUnlocked",
        "com.apple.screensaver.didstart",
        "com.apple.screensaver.didstop",
    ] {
        let name = name(text);
        if !name.0.is_null() {
            add(center, name.0 as _);
        }
    }
}
fn observe() {
    OBSERVE.call_once(|| {
        // A dedicated run loop continues receiving notifications while key prompts are open.
        let (ready, started) = std::sync::mpsc::channel();
        let _ = std::thread::Builder::new()
            .name("kv-presence-macos".into())
            .spawn(move || {
                let center = unsafe { CFNotificationCenterGetDistributedCenter() };
                register_notifications(center, cf_string, |center, name| unsafe {
                    CFNotificationCenterAddObserver(
                        center,
                        &LOCKED as *const AtomicI8 as *const c_void,
                        notification,
                        name,
                        std::ptr::null(),
                        CFNotificationSuspensionBehaviorDeliverImmediately,
                    );
                });
                let _ = ready.send(());
                unsafe {
                    CFRunLoopRun();
                }
            });
        let _ = started.recv_timeout(std::time::Duration::from_secs(1));
    });
}

#[derive(Clone, Default)]
pub struct MacSnapshot {
    pub console_user: Option<(String, u32)>,
    pub agent_uid: u32,
    pub screen_locked: Option<bool>,
    pub screensaver_active: Option<bool>,
    pub lock_notification: Option<bool>,
    pub screensaver_notification: Option<bool>,
    pub idle_seconds: Option<f64>,
    pub display_asleep: Option<Vec<bool>>,
}

pub trait MacSignals {
    fn snapshot(&self) -> MacSnapshot;
}

#[derive(Clone, Copy)]
struct MacApi {
    console: unsafe extern "C" fn(*const c_void, *mut u32, *mut u32) -> CFStringRef,
    session: unsafe extern "C" fn() -> CFDictionaryRef,
    idle: unsafe extern "C" fn(i32, u32) -> f64,
    displays: unsafe extern "C" fn(u32, *mut u32, *mut u32) -> i32,
    asleep: unsafe extern "C" fn(u32) -> u32,
}
impl Default for MacApi {
    fn default() -> Self {
        Self {
            console: SCDynamicStoreCopyConsoleUser,
            session: CGSessionCopyCurrentDictionary,
            idle: CGEventSourceSecondsSinceLastEventType,
            displays: CGGetActiveDisplayList,
            asleep: CGDisplayIsAsleep,
        }
    }
}
#[derive(Default)]
pub struct SystemMacSignals {
    api: MacApi,
}
impl MacSignals for SystemMacSignals {
    fn snapshot(&self) -> MacSnapshot {
        let mut uid = u32::MAX;
        let mut gid = u32::MAX;
        let console =
            Owned(unsafe { (self.api.console)(std::ptr::null(), &mut uid, &mut gid) } as _);
        let session = Owned(unsafe { (self.api.session)() } as _);
        let mut displays = [0u32; 64];
        let mut count = 0;
        let display_asleep = if unsafe {
            (self.api.displays)(displays.len() as u32, displays.as_mut_ptr(), &mut count)
        } == 0
            && count <= displays.len() as u32
        {
            Some(
                displays[..count as usize]
                    .iter()
                    .map(|d| unsafe { (self.api.asleep)(*d) } != 0)
                    .collect(),
            )
        } else {
            None
        };
        MacSnapshot {
            console_user: string(console.0 as _).map(|user| (user, uid)),
            agent_uid: unsafe { libc::geteuid() },
            screen_locked: boolean(session.0 as _, "CGSSessionScreenIsLocked"),
            screensaver_active: boolean(session.0 as _, "CGSSessionScreenSaverIsRunning"),
            lock_notification: cached(&LOCKED),
            screensaver_notification: cached(&SAVER),
            idle_seconds: Some(unsafe { (self.api.idle)(0, u32::MAX) }),
            display_asleep,
        }
    }
}

pub struct MacSignalSource<B = SystemMacSignals> {
    backend: B,
    owner_uid: u32,
    channel: Arc<dyn Fn() -> Option<bool> + Send + Sync>,
}
impl MacSignalSource<SystemMacSignals> {
    pub fn new(owner_uid: u32, channel: Arc<dyn Fn() -> Option<bool> + Send + Sync>) -> Self {
        observe();
        Self::with_backend(SystemMacSignals::default(), owner_uid, channel)
    }
}
impl<B: MacSignals> MacSignalSource<B> {
    pub fn with_backend(
        backend: B,
        owner_uid: u32,
        channel: Arc<dyn Fn() -> Option<bool> + Send + Sync>,
    ) -> Self {
        Self {
            backend,
            owner_uid,
            channel,
        }
    }
}
impl<B: MacSignals> SignalSource for MacSignalSource<B> {
    fn sample(&self) -> PresenceSignals {
        let snapshot = self.backend.snapshot();
        let mut signals = unavailable_signals();
        if let Some((user, uid)) = snapshot.console_user {
            signals
                .extra
                .insert("console_uid".into(), serde_json::json!(uid));
            let active = user != "loginwindow"
                && uid == self.owner_uid
                && snapshot.agent_uid == self.owner_uid;
            signals.graphical_session = Some(active);
            signals.session_active = Some(active);
        }
        let session_locked = snapshot.screen_locked;
        let session_saver = snapshot.screensaver_active;
        signals.extra.insert(
            "cg_session_locked".into(),
            serde_json::json!(session_locked),
        );
        signals.extra.insert(
            "cg_session_screensaver".into(),
            serde_json::json!(session_saver),
        );
        signals.screen_locked = match (session_locked, snapshot.lock_notification) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), _) | (_, Some(false)) => Some(false),
            _ => None,
        };
        // CONTRACT: §6.10.1: no notification history or dictionary value means unknown, not unlocked.
        signals.screensaver_active = match (session_saver, snapshot.screensaver_notification) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), _) | (_, Some(false)) => Some(false),
            _ => None,
        };
        let idle = snapshot.idle_seconds;
        signals
            .extra
            .insert("cg_idle_seconds".into(), serde_json::json!(idle));
        if let Some(idle) =
            idle.filter(|idle| idle.is_finite() && *idle >= 0.0 && *idle < u64::MAX as f64)
        {
            signals.idle_seconds = Some(idle as u64);
        }
        if let Some(asleep) = snapshot.display_asleep {
            let count = asleep.len();
            signals
                .extra
                .insert("active_display_count".into(), serde_json::json!(count));
            signals.display_connected = Some(count > 0);
            signals.display_awake = Some(asleep.iter().any(|asleep| !asleep));
            signals
                .extra
                .insert("display_asleep".into(), serde_json::json!(asleep));
        }
        // CONTRACT: §6.10.1: macOS V1 tracks the owner's console; only Windows/Linux expose remote-session presence.
        signals.remote_session_active = Some(false);
        signals.approval_channel_available = (self.channel)();
        signals.extra.insert(
            "lock_notification".into(),
            serde_json::json!(snapshot.lock_notification),
        );
        signals.extra.insert(
            "screensaver_notification".into(),
            serde_json::json!(snapshot.screensaver_notification),
        );
        signals
    }
}

#[cfg(test)]
mod tests {
    use super::super::{classify, Presence};
    use super::*;

    struct Fake(MacSnapshot);
    impl MacSignals for Fake {
        fn snapshot(&self) -> MacSnapshot {
            self.0.clone()
        }
    }
    fn present() -> MacSnapshot {
        MacSnapshot {
            console_user: Some(("owner".into(), 1000)),
            agent_uid: 1000,
            screen_locked: Some(false),
            screensaver_active: Some(false),
            idle_seconds: Some(0.0),
            display_asleep: Some(vec![false]),
            ..Default::default()
        }
    }
    fn sample(snapshot: MacSnapshot, channel: Option<bool>) -> PresenceSignals {
        MacSignalSource::with_backend(Fake(snapshot), 1000, Arc::new(move || channel)).sample()
    }

    #[test]
    fn injected_macos_signals_fail_closed_for_every_missing_group() {
        assert_eq!(
            classify(&sample(present(), Some(true)), 120),
            Presence::Present
        );
        for field in 0..6 {
            let mut snapshot = present();
            match field {
                0 => snapshot.console_user = None,
                1 => snapshot.screen_locked = None,
                2 => snapshot.screensaver_active = None,
                3 => snapshot.idle_seconds = None,
                4 => snapshot.display_asleep = None,
                _ => {}
            }
            let signals = sample(snapshot, if field == 5 { None } else { Some(true) });
            assert_eq!(classify(&signals, 120), Presence::Away);
        }
        for field in 0..7 {
            let mut snapshot = present();
            match field {
                0 => snapshot.console_user = Some(("loginwindow".into(), 1000)),
                1 => snapshot.console_user = Some(("another-owner".into(), 1001)),
                2 => snapshot.agent_uid = 0,
                3 => snapshot.screen_locked = Some(true),
                4 => snapshot.screensaver_active = Some(true),
                5 => snapshot.display_asleep = Some(vec![true]),
                _ => snapshot.display_asleep = Some(vec![]),
            }
            assert_eq!(classify(&sample(snapshot, Some(true)), 120), Presence::Away);
        }
        assert_eq!(
            classify(&sample(present(), Some(false)), 120),
            Presence::Away
        );
    }

    #[test]
    fn idle_boundaries_and_conflicting_notifications_preserve_conservative_values() {
        for (idle, expected) in [
            (119.9, Presence::Present),
            (120.0, Presence::Idle),
            (-1.0, Presence::Away),
            (f64::NAN, Presence::Away),
            (f64::INFINITY, Presence::Away),
            (u64::MAX as f64, Presence::Away),
        ] {
            let mut snapshot = present();
            snapshot.idle_seconds = Some(idle);
            assert_eq!(classify(&sample(snapshot, Some(true)), 120), expected);
        }
        for current in [None, Some(false), Some(true)] {
            for notification in [None, Some(false), Some(true)] {
                let mut snapshot = present();
                snapshot.screen_locked = current;
                snapshot.screensaver_active = current;
                snapshot.lock_notification = notification;
                snapshot.screensaver_notification = notification;
                let signals = sample(snapshot, Some(true));
                let expected = if current == Some(true) || notification == Some(true) {
                    Some(true)
                } else if current == Some(false) || notification == Some(false) {
                    Some(false)
                } else {
                    None
                };
                assert_eq!(signals.screen_locked, expected);
                assert_eq!(signals.screensaver_active, expected);
                assert_eq!(
                    signals.extra["lock_notification"],
                    serde_json::json!(notification)
                );
            }
        }
        let mut snapshot = present();
        snapshot.display_asleep = Some(vec![true, false]);
        let signals = sample(snapshot, Some(true));
        assert_eq!(signals.display_awake, Some(true));
        assert_eq!(signals.extra["active_display_count"], 2);
        assert_eq!(
            signals.extra["display_asleep"],
            serde_json::json!([true, false])
        );
    }

    #[test]
    fn core_foundation_values_and_notification_names_are_checked_without_gui() {
        use core_foundation_sys::dictionary::{
            kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks,
            CFDictionaryCreateMutable, CFDictionarySetValue,
        };
        use core_foundation_sys::number::{kCFBooleanFalse, kCFBooleanTrue};
        assert!(string(std::ptr::null()).is_none());
        assert!(string(cf_string(&"x".repeat(300)).0 as _).is_none());
        assert!(boolean(std::ptr::null(), "locked").is_none());
        let dict = Owned(unsafe {
            CFDictionaryCreateMutable(
                std::ptr::null(),
                0,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            )
        } as _);
        assert!(boolean_value(dict.0 as _, std::ptr::null()).is_none());
        assert!(boolean(dict.0 as _, "missing").is_none());
        let key = cf_string("locked");
        for (value, expected) in [
            (unsafe { kCFBooleanTrue } as CFTypeRef, Some(true)),
            (unsafe { kCFBooleanFalse } as CFTypeRef, Some(false)),
            (key.0, None),
        ] {
            unsafe {
                CFDictionarySetValue(dict.0 as _, key.0, value);
            }
            assert_eq!(boolean(dict.0 as _, "locked"), expected);
        }
        drop(Owned(std::ptr::null()));
        let lock = AtomicI8::new(-1);
        let active = AtomicI8::new(-1);
        assert_eq!(cached(&lock), None);
        for (name, locked, saver) in [
            ("com.apple.screenIsLocked", Some(true), None),
            ("com.apple.screenIsUnlocked", Some(false), None),
            ("com.apple.screensaver.didstart", Some(false), Some(true)),
            ("com.apple.screensaver.didstop", Some(false), Some(false)),
            ("unknown", Some(false), Some(false)),
        ] {
            let name = cf_string(name);
            notification_name(name.0 as _, &lock, &active);
            assert_eq!(cached(&lock), locked);
            assert_eq!(cached(&active), saver);
        }
        notification(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
    }

    unsafe extern "C" fn console(_: *const c_void, uid: *mut u32, gid: *mut u32) -> CFStringRef {
        unsafe {
            *uid = 1000;
            *gid = 1000;
        }
        let value = cf_string("owner");
        let result = value.0 as _;
        std::mem::forget(value);
        result
    }
    unsafe extern "C" fn no_console(_: *const c_void, _: *mut u32, _: *mut u32) -> CFStringRef {
        std::ptr::null()
    }
    unsafe extern "C" fn session() -> CFDictionaryRef {
        use core_foundation_sys::dictionary::{
            kCFTypeDictionaryKeyCallBacks, kCFTypeDictionaryValueCallBacks,
            CFDictionaryCreateMutable, CFDictionarySetValue,
        };
        let dict = unsafe {
            CFDictionaryCreateMutable(
                std::ptr::null(),
                0,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            )
        };
        for text in ["CGSSessionScreenIsLocked", "CGSSessionScreenSaverIsRunning"] {
            let key = cf_string(text);
            unsafe {
                CFDictionarySetValue(
                    dict,
                    key.0,
                    core_foundation_sys::number::kCFBooleanFalse as _,
                );
            }
        }
        dict
    }
    unsafe extern "C" fn no_session() -> CFDictionaryRef {
        std::ptr::null()
    }
    unsafe extern "C" fn idle(state: i32, event: u32) -> f64 {
        assert_eq!((state, event), (0, u32::MAX));
        17.0
    }
    unsafe extern "C" fn displays(max: u32, list: *mut u32, count: *mut u32) -> i32 {
        assert_eq!(max, 64);
        unsafe {
            *list = 10;
            *list.add(1) = 20;
            *count = 2;
        }
        0
    }
    unsafe extern "C" fn no_displays(_: u32, _: *mut u32, count: *mut u32) -> i32 {
        unsafe { *count = 0 };
        0
    }
    unsafe extern "C" fn excess_displays(_: u32, _: *mut u32, count: *mut u32) -> i32 {
        unsafe { *count = 65 };
        0
    }
    unsafe extern "C" fn display_error(_: u32, _: *mut u32, _: *mut u32) -> i32 {
        1
    }
    unsafe extern "C" fn asleep(display: u32) -> u32 {
        u32::from(display == 10)
    }

    #[test]
    fn native_snapshot_checks_buffer_bounds_and_missing_cf_values_with_injected_apis() {
        let api = MacApi {
            console,
            session,
            idle,
            displays,
            asleep,
        };
        let snapshot = SystemMacSignals { api }.snapshot();
        assert_eq!(snapshot.console_user, Some(("owner".into(), 1000)));
        assert_eq!(snapshot.agent_uid, unsafe { libc::geteuid() });
        assert_eq!(snapshot.screen_locked, Some(false));
        assert_eq!(snapshot.screensaver_active, Some(false));
        assert_eq!(snapshot.idle_seconds, Some(17.0));
        assert_eq!(snapshot.display_asleep, Some(vec![true, false]));
        for displays in [excess_displays as _, display_error as _] {
            let snapshot = SystemMacSignals {
                api: MacApi {
                    console: no_console,
                    session: no_session,
                    displays,
                    ..api
                },
            }
            .snapshot();
            assert!(snapshot.console_user.is_none());
            assert!(snapshot.screen_locked.is_none());
            assert!(snapshot.screensaver_active.is_none());
            assert!(snapshot.display_asleep.is_none());
        }
        assert_eq!(
            SystemMacSignals {
                api: MacApi {
                    displays: no_displays,
                    ..api
                }
            }
            .snapshot()
            .display_asleep,
            Some(vec![])
        );
    }

    #[test]
    fn notification_registration_skips_unavailable_center_or_name_without_gui() {
        let center = std::ptr::dangling_mut::<c_void>() as _;
        let mut names = Vec::new();
        register_notifications(center, cf_string, |received, name| {
            assert_eq!(received, center);
            names.push(string(name).unwrap());
        });
        assert_eq!(
            names,
            [
                "com.apple.screenIsLocked",
                "com.apple.screenIsUnlocked",
                "com.apple.screensaver.didstart",
                "com.apple.screensaver.didstop"
            ]
        );
        register_notifications(
            std::ptr::null_mut(),
            |_| panic!("unavailable center"),
            |_, _| panic!("unavailable center"),
        );
        register_notifications(
            center,
            |_| Owned(std::ptr::null()),
            |_, _| panic!("unavailable name"),
        );
        // Registering notifications needs no GUI state or installed agent.
        let _ = MacSignalSource::new(unsafe { libc::geteuid() }, Arc::new(|| None));
    }

    /// Run on the vault owner's logged-in Mac:
    /// CARGO_TARGET_DIR=target-w1 cargo test -p kv-platform macos_presence_smoke -- --ignored
    #[test]
    #[ignore = "Requires a real macOS GUI session"]
    fn macos_presence_smoke() {
        let source = MacSignalSource::new(unsafe { libc::geteuid() }, Arc::new(|| Some(true)));
        let signals = source.sample();
        assert_eq!(signals.graphical_session, Some(true));
        assert!(signals.idle_seconds.is_some());
        assert!(signals.display_connected.is_some());
        println!("macos_presence console=available input=available displays=available lock_known={} screensaver_known={}",
            signals.screen_locked.is_some(),signals.screensaver_active.is_some());
    }
}
