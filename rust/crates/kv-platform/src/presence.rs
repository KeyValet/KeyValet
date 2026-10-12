//! Local presence affects delivery, never authorization.
pub use kv_ipc::remote::{Presence, PresenceProbe, PresenceSignals, PresenceState};
use std::sync::Mutex;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;
pub mod windows_logic;

pub const IDLE_THRESHOLD_SECONDS: u64 = 120;
pub const DEBOUNCE_SECONDS: i64 = 5;

pub trait SignalSource {
    fn sample(&self) -> PresenceSignals;
}

pub fn unavailable_signals() -> PresenceSignals {
    PresenceSignals {
        graphical_session: None,
        session_active: None,
        screen_locked: None,
        screensaver_active: None,
        idle_seconds: None,
        display_connected: None,
        display_awake: None,
        remote_session_active: None,
        approval_channel_available: None,
        extra: Default::default(),
    }
}

pub fn classify(signals: &PresenceSignals, idle_threshold: u64) -> Presence {
    let complete = signals.graphical_session == Some(true)
        && signals.session_active == Some(true)
        && signals.screen_locked == Some(false)
        && signals.screensaver_active == Some(false)
        && signals.display_connected.is_some()
        && signals.display_awake.is_some()
        && signals.remote_session_active.is_some()
        && signals.approval_channel_available == Some(true);
    if !complete
        || !((signals.display_connected == Some(true) && signals.display_awake == Some(true))
            || signals.remote_session_active == Some(true))
    {
        return Presence::Away;
    }
    match signals.idle_seconds {
        Some(seconds) if seconds < idle_threshold => Presence::Present,
        Some(_) => Presence::Idle,
        None => Presence::Away,
    }
}

struct Tracking {
    state: Presence,
    since: i64,
    pending: Option<(Presence, i64)>,
    last_sample: i64,
}

pub struct DebouncedPresence<S> {
    source: S,
    threshold: u64,
    tracking: Mutex<Tracking>,
}

impl<S: SignalSource> DebouncedPresence<S> {
    pub fn new(source: S, idle_threshold: u64, now: i64) -> Self {
        Self {
            source,
            threshold: idle_threshold.max(1),
            tracking: Mutex::new(Tracking {
                state: Presence::Away,
                since: now,
                pending: None,
                last_sample: now,
            }),
        }
    }

    pub fn poll(&self, now: i64) -> PresenceState {
        let signals = self.source.sample();
        let next = classify(&signals, self.threshold);
        let mut tracking = self.tracking.lock().unwrap_or_else(|e| e.into_inner());
        if now < tracking.last_sample {
            tracking.state = Presence::Away;
            tracking.since = now;
            tracking.pending = None;
        }
        tracking.last_sample = now;
        if next == tracking.state {
            tracking.pending = None;
        } else {
            match tracking.pending {
                Some((candidate, started)) if candidate == next => {
                    if now.saturating_sub(started) >= DEBOUNCE_SECONDS {
                        tracking.state = next;
                        tracking.since = started;
                        tracking.pending = None;
                    }
                }
                _ => tracking.pending = Some((next, now)),
            }
        }
        PresenceState {
            state: tracking.state,
            since: tracking.since,
            signals,
            extra: Default::default(),
        }
    }
}

pub fn unix_seconds() -> i64 {
    seconds_since_epoch(std::time::SystemTime::now())
}

fn seconds_since_epoch(time: std::time::SystemTime) -> i64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

impl<S: SignalSource> PresenceProbe for DebouncedPresence<S> {
    fn state(&self) -> PresenceState {
        self.poll(unix_seconds())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn present() -> PresenceSignals {
        PresenceSignals {
            graphical_session: Some(true),
            session_active: Some(true),
            screen_locked: Some(false),
            screensaver_active: Some(false),
            idle_seconds: Some(0),
            display_connected: Some(true),
            display_awake: Some(true),
            remote_session_active: Some(false),
            approval_channel_available: Some(true),
            extra: Default::default(),
        }
    }

    #[test]
    fn probe_uses_the_clock_and_never_accepts_zero_idle_threshold() {
        struct Present;
        impl SignalSource for Present {
            fn sample(&self) -> PresenceSignals {
                present()
            }
        }
        let probe = DebouncedPresence::new(Present, 0, 0);
        let state = PresenceProbe::state(&probe);
        assert_eq!(state.state, Presence::Away);
        assert!(state.signals.graphical_session == Some(true));
        assert!(unix_seconds() > 0);
        assert_eq!(probe.poll(state.since + 5).state, Presence::Away);
        assert_eq!(seconds_since_epoch(std::time::UNIX_EPOCH), 0);
        assert_eq!(
            seconds_since_epoch(std::time::UNIX_EPOCH - std::time::Duration::from_secs(1)),
            0
        );
        assert_eq!(
            seconds_since_epoch(std::time::UNIX_EPOCH + std::time::Duration::from_secs(17)),
            17
        );
        let mut signals = present();
        signals.idle_seconds = Some(1);
        assert_eq!(classify(&signals, probe.threshold), Presence::Idle);
    }

    #[test]
    fn each_missing_signal_is_away() {
        for field in 0..9 {
            let mut s = present();
            match field {
                0 => s.graphical_session = None,
                1 => s.session_active = None,
                2 => s.screen_locked = None,
                3 => s.screensaver_active = None,
                4 => s.idle_seconds = None,
                5 => s.display_connected = None,
                6 => s.display_awake = None,
                7 => s.remote_session_active = None,
                _ => s.approval_channel_available = None,
            }
            assert_eq!(classify(&s, 120), Presence::Away, "missing field {field}");
        }
    }

    #[test]
    fn inactive_locked_disconnected_and_unavailable_channels_are_away() {
        for field in 0..7 {
            let mut s = present();
            match field {
                0 => s.graphical_session = Some(false),
                1 => s.session_active = Some(false),
                2 => s.screen_locked = Some(true),
                3 => s.screensaver_active = Some(true),
                4 => s.display_connected = Some(false),
                5 => s.display_awake = Some(false),
                _ => s.approval_channel_available = Some(false),
            }
            assert_eq!(classify(&s, 120), Presence::Away);
        }
        let mut remote = present();
        remote.display_connected = Some(false);
        remote.display_awake = Some(false);
        remote.remote_session_active = Some(true);
        assert_eq!(classify(&remote, 120), Presence::Present);
        remote.session_active = Some(false);
        assert_eq!(classify(&remote, 120), Presence::Away);
    }

    #[test]
    fn idle_boundary_and_all_debounce_transitions() {
        struct Fake(Arc<Mutex<PresenceSignals>>);
        impl SignalSource for Fake {
            fn sample(&self) -> PresenceSignals {
                self.0.lock().unwrap().clone()
            }
        }
        let source = Arc::new(Mutex::new(present()));
        let probe = DebouncedPresence::new(Fake(source.clone()), 120, 100);
        assert_eq!(probe.poll(100).state, Presence::Away);
        assert_eq!(probe.poll(104).state, Presence::Away);
        assert_eq!(probe.poll(105).state, Presence::Present);
        assert_eq!(probe.poll(105).since, 100);
        source.lock().unwrap().idle_seconds = Some(119);
        assert_eq!(probe.poll(106).state, Presence::Present);
        source.lock().unwrap().idle_seconds = Some(120);
        assert_eq!(probe.poll(107).state, Presence::Present);
        assert_eq!(probe.poll(112).state, Presence::Idle);
        source.lock().unwrap().screen_locked = Some(true);
        probe.poll(113);
        source.lock().unwrap().screen_locked = Some(false);
        assert_eq!(probe.poll(114).state, Presence::Idle);
        source.lock().unwrap().approval_channel_available = None;
        probe.poll(115);
        assert_eq!(probe.poll(120).state, Presence::Away);
        *source.lock().unwrap() = present();
        probe.poll(121);
        source.lock().unwrap().idle_seconds = Some(200);
        probe.poll(122);
        assert_eq!(probe.poll(126).state, Presence::Away);
        assert_eq!(probe.poll(127).state, Presence::Idle);
        assert_eq!(probe.poll(10).state, Presence::Away);
    }

    #[test]
    fn every_pair_of_states_requires_five_continuous_seconds() {
        struct Fake(Arc<Mutex<PresenceSignals>>);
        impl SignalSource for Fake {
            fn sample(&self) -> PresenceSignals {
                self.0.lock().unwrap().clone()
            }
        }
        let signals = |state| {
            let mut signals = present();
            match state {
                Presence::Present => {}
                Presence::Idle => signals.idle_seconds = Some(120),
                Presence::Away => signals.screen_locked = Some(true),
            }
            signals
        };
        for before in [Presence::Present, Presence::Idle, Presence::Away] {
            for after in [Presence::Present, Presence::Idle, Presence::Away] {
                if before == after {
                    continue;
                }
                let source = Arc::new(Mutex::new(signals(before)));
                let probe = DebouncedPresence::new(Fake(source.clone()), 120, 100);
                probe.poll(100);
                assert_eq!(probe.poll(105).state, before);
                *source.lock().unwrap() = signals(after);
                assert_eq!(probe.poll(110).state, before);
                assert_eq!(probe.poll(114).state, before);
                let changed = probe.poll(115);
                assert_eq!(changed.state, after);
                assert_eq!(changed.since, 110);
            }
        }
    }
}
