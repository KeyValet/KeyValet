use kv_ipc::remote::{Op, PresenceProbe, Request};
use serde_json::json;
use std::io;

#[cfg(windows)]
pub mod windows;

pub trait PresenceSink {
    /// Return success only after the authenticated helper accepts the update.
    fn send(&mut self, request: &Request) -> io::Result<()>;
}

pub struct PresenceReporter {
    device_id: String,
    accepted: Option<(kv_ipc::remote::Presence, i64)>,
    last_sent: Option<i64>,
}

impl PresenceReporter {
    /// The helper supplies the device id after authenticating the agent's owner identity.
    pub fn new(device_id: String) -> Self {
        Self {
            device_id,
            accepted: None,
            last_sent: None,
        }
    }

    // CONTRACT: §6.10.1 / A.6 / Appendix C: signals stay local; report the debounced coarse hint.
    pub fn update(
        &mut self,
        probe: &dyn PresenceProbe,
        sink: &mut dyn PresenceSink,
        now: i64,
    ) -> io::Result<bool> {
        let state = probe.state();
        let key = (state.state, state.since);
        // CONTRACT: §6.10.1 / §16 / A.6: refresh unchanged hints every 60 seconds;
        // a debounced state change is sent immediately so locks do not wait for a heartbeat.
        if self.accepted == Some(key)
            && self
                .last_sent
                .is_some_and(|sent| now >= sent && now.saturating_sub(sent) < 60)
        {
            return Ok(false);
        }
        let request = Request {
            op: Op::PresenceUpdate,
            params: json!({"device_id":self.device_id,"state":state.state,"since":state.since,"sent_at":now}),
            extra: Default::default(),
        };
        sink.send(&request)?;
        self.accepted = Some(key);
        self.last_sent = Some(now);
        Ok(true)
    }

    pub fn reconnect(&mut self) {
        self.accepted = None;
        self.last_sent = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kv_ipc::remote::{Presence, PresenceSignals, PresenceState, PRESENCE_UPDATE};
    use std::sync::Mutex;

    struct Probe(Mutex<PresenceState>);
    impl PresenceProbe for Probe {
        fn state(&self) -> PresenceState {
            self.0.lock().unwrap().clone()
        }
    }
    struct Sink {
        requests: Vec<Request>,
        fail: bool,
    }
    impl PresenceSink for Sink {
        fn send(&mut self, request: &Request) -> io::Result<()> {
            if self.fail {
                self.fail = false;
                return Err(io::Error::other("helper unavailable"));
            }
            self.requests.push(request.clone());
            Ok(())
        }
    }
    #[test]
    fn missing_receiver_retries_and_reports_only_coarse_changes() {
        let probe = Probe(Mutex::new(PresenceState {
            state: Presence::Away,
            since: 10,
            signals: PresenceSignals {
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
            },
            extra: Default::default(),
        }));
        let mut reporter = PresenceReporter::new("dev_test".into());
        let mut sink = Sink {
            requests: Vec::new(),
            fail: true,
        };
        assert!(reporter.update(&probe, &mut sink, 10).is_err());
        assert!(reporter.update(&probe, &mut sink, 11).unwrap());
        assert!(!reporter.update(&probe, &mut sink, 12).unwrap());
        probe.0.lock().unwrap().signals.idle_seconds = Some(40);
        assert!(!reporter.update(&probe, &mut sink, 13).unwrap());
        {
            let mut state = probe.0.lock().unwrap();
            state.state = Presence::Present;
            state.since = 14;
        }
        assert!(reporter.update(&probe, &mut sink, 19).unwrap());
        let request = serde_json::to_value(&sink.requests[1]).unwrap();
        assert_eq!(request["op"], PRESENCE_UPDATE);
        assert_eq!(
            request["params"],
            json!({"device_id":"dev_test","state":"present","since":14,"sent_at":19})
        );
        assert!(!reporter.update(&probe, &mut sink, 78).unwrap());
        assert!(reporter.update(&probe, &mut sink, 79).unwrap());
        assert_eq!(sink.requests.len(), 3);
        reporter.reconnect();
        assert!(reporter.update(&probe, &mut sink, 80).unwrap());
    }

    #[test]
    fn failed_heartbeat_and_state_changes_retry_and_clock_regression_refreshes() {
        let probe = Probe(Mutex::new(PresenceState {
            state: Presence::Away,
            since: 0,
            signals: serde_json::from_value(json!({})).unwrap(),
            extra: Default::default(),
        }));
        let mut sink = Sink {
            requests: Vec::new(),
            fail: false,
        };
        let mut reporter = PresenceReporter::new("dev_test".into());
        assert!(reporter.update(&probe, &mut sink, 0).unwrap());
        sink.fail = true;
        assert!(reporter.update(&probe, &mut sink, 60).is_err());
        assert!(reporter.update(&probe, &mut sink, 61).unwrap());
        probe.0.lock().unwrap().state = Presence::Idle;
        sink.fail = true;
        assert!(reporter.update(&probe, &mut sink, 62).is_err());
        assert!(reporter.update(&probe, &mut sink, 63).unwrap());
        assert!(reporter.update(&probe, &mut sink, 1).unwrap());
        assert!(!reporter.update(&probe, &mut sink, 2).unwrap());
        assert_eq!(sink.requests.len(), 4);
    }
}
