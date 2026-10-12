use super::{unavailable_signals, PresenceSignals, SignalSource};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct WindowsSnapshot {
    pub session: Option<(u32, bool)>,
    pub session_state: Option<i32>,
    pub protocol: Option<u16>,
    pub console_session: u32,
    pub observer_registered: bool,
    pub session_flags: Option<i32>,
    pub lock_notification: Option<bool>,
    pub display_notification: Option<bool>,
    pub screensaver_active: Option<bool>,
    pub last_input_tick: Option<u32>,
    pub current_tick: u32,
    pub display_connected: Option<bool>,
}

pub trait WindowsSignals {
    fn snapshot(&self) -> WindowsSnapshot;
}

pub struct WindowsProbeSignals<B> {
    backend: B,
    hello: Arc<dyn Fn() -> Option<bool> + Send + Sync>,
}
impl<B: WindowsSignals> WindowsProbeSignals<B> {
    pub fn with_backend(backend: B, hello: Arc<dyn Fn() -> Option<bool> + Send + Sync>) -> Self {
        Self { backend, hello }
    }
}
impl<B: WindowsSignals> SignalSource for WindowsProbeSignals<B> {
    fn sample(&self) -> PresenceSignals {
        let snapshot = self.backend.snapshot();
        let mut signals = unavailable_signals();
        let Some((session, owner)) = snapshot.session else {
            return signals;
        };
        signals.graphical_session = Some(owner);
        signals.session_active = snapshot.session_state.map(|state| owner && state == 0);
        signals.extra.insert(
            "wts_session_state".into(),
            serde_json::json!(snapshot.session_state),
        );
        if snapshot.protocol == Some(0) && snapshot.console_session != session {
            signals.session_active = Some(false);
        }
        signals.remote_session_active = snapshot
            .protocol
            .zip(signals.session_active)
            .map(|(protocol, active)| protocol == 2 && active);
        if snapshot.observer_registered {
            let initial = match snapshot.session_flags {
                Some(0) => Some(true),
                Some(1) => Some(false),
                _ => None,
            };
            signals.screen_locked = match (initial, snapshot.lock_notification) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), _) | (_, Some(false)) => Some(false),
                _ => None,
            };
            signals.display_awake = snapshot.display_notification;
            signals.extra.insert(
                "wts_session_flags".into(),
                serde_json::json!(snapshot.session_flags),
            );
            signals.extra.insert(
                "lock_notification".into(),
                serde_json::json!(snapshot.lock_notification),
            );
            signals.extra.insert(
                "display_notification".into(),
                serde_json::json!(snapshot.display_notification),
            );
        }
        signals.screensaver_active = snapshot.screensaver_active;
        if owner {
            if let Some(tick) = snapshot.last_input_tick {
                signals.idle_seconds = Some(snapshot.current_tick.wrapping_sub(tick) as u64 / 1000);
                signals
                    .extra
                    .insert("last_input_tick".into(), serde_json::json!(tick));
            }
        }
        signals.display_connected = snapshot.display_connected;
        if signals.remote_session_active == Some(true) && signals.display_awake.is_none() {
            // CONTRACT: §6.10.1: an active RDP session has an awake virtual display without a console power event.
            signals.display_awake = Some(true);
        }
        signals.approval_channel_available = (self.hello)();
        signals.extra.insert(
            "console_session".into(),
            serde_json::json!(snapshot.console_session),
        );
        signals
            .extra
            .insert("wts_protocol".into(), serde_json::json!(snapshot.protocol));
        signals
    }
}

#[cfg(test)]
mod tests {
    use super::super::{classify, Presence};
    use super::*;

    struct Fake(WindowsSnapshot);
    impl WindowsSignals for Fake {
        fn snapshot(&self) -> WindowsSnapshot {
            self.0.clone()
        }
    }
    fn present() -> WindowsSnapshot {
        WindowsSnapshot {
            session: Some((1, true)),
            session_state: Some(0),
            protocol: Some(0),
            console_session: 1,
            observer_registered: true,
            session_flags: Some(1),
            display_notification: Some(true),
            screensaver_active: Some(false),
            last_input_tick: Some(0),
            current_tick: 1000,
            display_connected: Some(true),
            ..Default::default()
        }
    }
    fn sample(snapshot: WindowsSnapshot, available: Option<bool>) -> PresenceSignals {
        WindowsProbeSignals::with_backend(Fake(snapshot), Arc::new(move || available)).sample()
    }
    #[test]
    fn every_missing_windows_signal_is_away_without_a_session_or_hardware() {
        assert_eq!(
            classify(&sample(present(), Some(true)), 120),
            Presence::Present
        );
        for field in 0..10 {
            let mut snapshot = present();
            match field {
                0 => snapshot.session = None,
                1 => snapshot.session_state = None,
                2 => snapshot.protocol = None,
                3 => snapshot.observer_registered = false,
                4 => snapshot.session_flags = None,
                5 => snapshot.display_notification = None,
                6 => snapshot.screensaver_active = None,
                7 => snapshot.last_input_tick = None,
                8 => snapshot.display_connected = None,
                _ => {}
            }
            assert_eq!(
                classify(
                    &sample(snapshot, if field == 9 { None } else { Some(true) }),
                    120
                ),
                Presence::Away
            );
        }
    }
    #[test]
    fn disconnected_switched_locked_and_unavailable_windows_sessions_are_away() {
        for field in 0..9 {
            let mut snapshot = present();
            match field {
                0 => snapshot.session = Some((0, false)),
                1 => snapshot.session_state = Some(4),
                2 => snapshot.console_session = 2,
                3 => snapshot.session_flags = Some(0),
                4 => snapshot.session_flags = Some(-1),
                5 => snapshot.lock_notification = Some(true),
                6 => snapshot.display_notification = Some(false),
                7 => snapshot.screensaver_active = Some(true),
                _ => snapshot.display_connected = Some(false),
            }
            assert_eq!(classify(&sample(snapshot, Some(true)), 120), Presence::Away);
        }
        assert_eq!(
            classify(&sample(present(), Some(false)), 120),
            Presence::Away
        );
    }
    #[test]
    fn rdp_virtual_display_tick_wrap_and_notification_conflicts_preserve_raw_values() {
        let mut snapshot = present();
        snapshot.protocol = Some(2);
        snapshot.display_notification = None;
        snapshot.display_connected = Some(false);
        let signals = sample(snapshot, Some(true));
        assert_eq!(classify(&signals, 120), Presence::Present);
        assert_eq!(signals.remote_session_active, Some(true));
        assert_eq!(signals.display_awake, Some(true));
        assert_eq!(signals.extra["wts_protocol"], 2);
        for (tick, now, expected) in [
            (0, 119_999, Presence::Present),
            (0, 120_000, Presence::Idle),
            (u32::MAX - 999, 1000, Presence::Present),
        ] {
            let mut snapshot = present();
            snapshot.last_input_tick = Some(tick);
            snapshot.current_tick = now;
            let signals = sample(snapshot, Some(true));
            assert_eq!(classify(&signals, 120), expected);
            assert_eq!(signals.extra["last_input_tick"], tick);
        }
        for flags in [None, Some(-1), Some(0), Some(1)] {
            for notification in [None, Some(false), Some(true)] {
                let mut snapshot = present();
                snapshot.session_flags = flags;
                snapshot.lock_notification = notification;
                let signals = sample(snapshot, Some(true));
                let expected = if flags == Some(0) || notification == Some(true) {
                    Some(true)
                } else if flags == Some(1) || notification == Some(false) {
                    Some(false)
                } else {
                    None
                };
                assert_eq!(signals.screen_locked, expected);
                assert_eq!(signals.extra["wts_session_flags"], serde_json::json!(flags));
            }
        }
    }
}
