use super::{
    unavailable_signals, unix_seconds, PresenceSignals, SignalSource, IDLE_THRESHOLD_SECONDS,
};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub trait LoginSignals {
    fn busctl(&self, user_bus: bool, args: &[&str]) -> Option<String>;
    fn displays(&self) -> Option<(bool, Option<bool>)>;
}
pub struct SystemLoginSignals {
    pub owner_uid: u32,
}
impl LoginSignals for SystemLoginSignals {
    fn busctl(&self, user_bus: bool, args: &[&str]) -> Option<String> {
        query_bus(
            self.owner_uid,
            user_bus,
            args,
            Path::new("/run/user"),
            || crate::linux::trusted_command("/usr/bin/busctl").map_err(std::io::Error::other),
        )
    }
    fn displays(&self) -> Option<(bool, Option<bool>)> {
        drm_displays(Path::new("/sys/class/drm"))
    }
}
fn query_bus(
    owner_uid: u32,
    user_bus: bool,
    args: &[&str],
    runtime_root: &Path,
    command: impl FnOnce() -> std::io::Result<std::process::Command>,
) -> Option<String> {
    if owner_uid != unsafe { libc::geteuid() } {
        return None;
    }
    let mut command = command().ok()?;
    command
        .arg(if user_bus { "--user" } else { "--system" })
        .arg("--timeout=2s");
    if user_bus {
        let runtime = runtime_root.join(owner_uid.to_string());
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(&runtime).ok()?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != owner_uid
            || meta.mode() & 0o077 != 0
        {
            return None;
        }
        command.env("XDG_RUNTIME_DIR", runtime);
    }
    let output =
        crate::remote_process::bounded_output(command.args(args), 4096, Duration::from_secs(3))
            .ok()?;
    String::from_utf8(output.to_vec()).ok()
}
fn drm_displays(root: &Path) -> Option<(bool, Option<bool>)> {
    let mut connected = false;
    let mut awake = false;
    let mut unknown = false;
    for entry in std::fs::read_dir(root).ok()? {
        let entry = entry.ok()?;
        let status = entry.path().join("status");
        if !status.try_exists().ok()? {
            continue;
        }
        match std::fs::read_to_string(status).ok()?.trim() {
            "connected" => {
                connected = true;
                match std::fs::read_to_string(entry.path().join("dpms"))
                    .ok()
                    .as_deref()
                    .map(str::trim)
                {
                    Some("On") => awake = true,
                    Some("Off" | "Standby" | "Suspend") => {}
                    _ => unknown = true,
                }
            }
            "disconnected" => {}
            _ => return None,
        }
    }
    Some((
        connected,
        if awake {
            Some(true)
        } else if unknown {
            None
        } else {
            Some(false)
        },
    ))
}

pub struct LinuxSignalSource<B = SystemLoginSignals> {
    backend: B,
    owner_uid: u32,
    pid: u32,
    polkit: Arc<dyn Fn() -> Option<bool> + Send + Sync>,
}
impl LinuxSignalSource<SystemLoginSignals> {
    pub fn new(owner_uid: u32, polkit: Arc<dyn Fn() -> Option<bool> + Send + Sync>) -> Self {
        Self::with_backend(
            SystemLoginSignals { owner_uid },
            owner_uid,
            std::process::id(),
            polkit,
        )
    }
}
impl<B: LoginSignals> LinuxSignalSource<B> {
    // The agent supplies registration evidence; seeing a polkit process is not registration.
    pub fn with_backend(
        backend: B,
        owner_uid: u32,
        pid: u32,
        polkit: Arc<dyn Fn() -> Option<bool> + Send + Sync>,
    ) -> Self {
        Self {
            backend,
            owner_uid,
            pid,
            polkit,
        }
    }
    fn property(&self, path: &str, name: &str) -> Option<String> {
        self.backend.busctl(
            false,
            &[
                "get-property",
                "org.freedesktop.login1",
                path,
                "org.freedesktop.login1.Session",
                name,
            ],
        )
    }
}
fn bool_value(raw: Option<String>) -> Option<bool> {
    match raw.as_deref().map(str::trim) {
        Some("b true") => Some(true),
        Some("b false") => Some(false),
        _ => None,
    }
}
fn quoted(raw: &str, prefix: &str) -> Option<String> {
    let value = raw.trim().strip_prefix(prefix)?;
    serde_json::from_str::<String>(value).ok()
}
impl<B: LoginSignals> SignalSource for LinuxSignalSource<B> {
    fn sample(&self) -> PresenceSignals {
        let mut signals = unavailable_signals();
        let pid = self.pid.to_string();
        let Some(path) = self
            .backend
            .busctl(
                false,
                &[
                    "call",
                    "org.freedesktop.login1",
                    "/org/freedesktop/login1",
                    "org.freedesktop.login1.Manager",
                    "GetSessionByPID",
                    "u",
                    &pid,
                ],
            )
            .and_then(|s| quoted(&s, "o "))
        else {
            return signals;
        };
        if !path.starts_with("/org/freedesktop/login1/session/")
            || !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_".contains(&b))
        {
            return signals;
        }
        let user = self.property(&path, "User").and_then(|s| {
            let mut values = s.split_whitespace();
            (values.next() == Some("(uo)"))
                .then(|| values.next()?.parse::<u32>().ok())
                .flatten()
        });
        let kind = self.property(&path, "Type").and_then(|s| quoted(&s, "s "));
        signals
            .extra
            .insert("logind_user".into(), serde_json::json!(user));
        signals
            .extra
            .insert("logind_type".into(), serde_json::json!(kind));
        signals.graphical_session = user
            .zip(kind.as_deref())
            .map(|(uid, kind)| uid == self.owner_uid && matches!(kind, "x11" | "wayland"));
        let active = bool_value(self.property(&path, "Active"));
        let state = self.property(&path, "State").and_then(|s| quoted(&s, "s "));
        signals
            .extra
            .insert("logind_active".into(), serde_json::json!(active));
        signals
            .extra
            .insert("logind_state".into(), serde_json::json!(state));
        signals.session_active = active
            .zip(state.as_deref())
            .map(|(active, state)| active && state == "active");
        signals.screen_locked = bool_value(self.property(&path, "LockedHint"));
        signals.screensaver_active = bool_value(self.backend.busctl(
            true,
            &[
                "call",
                "org.freedesktop.ScreenSaver",
                "/org/freedesktop/ScreenSaver",
                "org.freedesktop.ScreenSaver",
                "GetActive",
            ],
        ));
        let idle = bool_value(self.property(&path, "IdleHint"));
        let since = self
            .property(&path, "IdleSinceHint")
            .and_then(|s| s.trim().strip_prefix("t ")?.parse::<u64>().ok());
        // CONTRACT: §6.10.1: logind provides a hint, not exact keystroke age. A missing hint/timestamp remains unknown.
        signals.idle_seconds = idle.zip(since).and_then(|(idle, since)| {
            let now = unix_seconds().max(0) as u64;
            let since = since / 1_000_000;
            if since == 0 || since > now {
                return None;
            }
            Some(if idle {
                now - since + IDLE_THRESHOLD_SECONDS
            } else {
                0
            })
        });
        if let Some((connected, awake)) = self.backend.displays() {
            signals.display_connected = Some(connected);
            signals.display_awake = awake;
        }
        signals.remote_session_active = bool_value(self.property(&path, "Remote"))
            .zip(signals.session_active)
            .map(|(remote, active)| remote && active);
        signals.approval_channel_available = (self.polkit)();
        signals
            .extra
            .insert("logind_idle_hint".into(), serde_json::json!(idle));
        signals
            .extra
            .insert("logind_idle_since_us".into(), serde_json::json!(since));
        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drm_missing_power_and_unknown_connector_fail_conservatively() {
        let dir = tempfile::tempdir().unwrap();
        let connector = dir.path().join("card0-HDMI-A-1");
        std::fs::create_dir(&connector).unwrap();
        std::fs::write(connector.join("status"), "connected\n").unwrap();
        assert_eq!(drm_displays(dir.path()), Some((true, None)));
        std::fs::write(connector.join("dpms"), "On\n").unwrap();
        assert_eq!(drm_displays(dir.path()), Some((true, Some(true))));
        std::fs::write(connector.join("status"), "unknown\n").unwrap();
        assert_eq!(drm_displays(dir.path()), None);
        std::fs::write(connector.join("status"), "connected").unwrap();
        for state in ["Off", "Standby", "Suspend"] {
            std::fs::write(connector.join("dpms"), state).unwrap();
            assert_eq!(drm_displays(dir.path()), Some((true, Some(false))));
        }
        std::fs::write(connector.join("status"), "disconnected").unwrap();
        assert_eq!(drm_displays(dir.path()), Some((false, Some(false))));
        std::fs::create_dir(dir.path().join("card0")).unwrap();
        assert_eq!(drm_displays(dir.path()), Some((false, Some(false))));
        assert_eq!(drm_displays(&dir.path().join("missing")), None);
        std::fs::remove_file(connector.join("status")).unwrap();
        std::os::unix::fs::symlink("status", connector.join("status")).unwrap();
        assert_eq!(drm_displays(dir.path()), None);
    }
    #[test]
    fn absent_dbus_and_polkit_are_not_present() {
        struct Missing;
        impl LoginSignals for Missing {
            fn busctl(&self, _: bool, _: &[&str]) -> Option<String> {
                None
            }
            fn displays(&self) -> Option<(bool, Option<bool>)> {
                None
            }
        }
        let source = LinuxSignalSource::with_backend(Missing, 1000, 1, Arc::new(|| Some(true)));
        assert_eq!(
            super::super::classify(&source.sample(), 120),
            super::super::Presence::Away
        );
        assert_eq!(bool_value(Some("b false".into())), Some(false));
        assert_eq!(bool_value(Some("b unknown".into())), None);
        let owner = unsafe { libc::geteuid() };
        let source = LinuxSignalSource::new(owner, Arc::new(|| None));
        assert_eq!(source.owner_uid, owner);
        let other = SystemLoginSignals {
            owner_uid: owner.wrapping_add(1),
        };
        assert_eq!(other.busctl(false, &[]), None);
    }

    #[test]
    fn bus_query_checks_owner_private_runtime_utf8_and_output_bounds() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let owner = unsafe { libc::geteuid() };
        let runtime = dir.path().join(owner.to_string());
        let run = |script: &str| {
            let mut command = std::process::Command::new("/bin/sh");
            command
                .args(["-c", script])
                .env_clear()
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            Ok(command)
        };
        assert_eq!(
            query_bus(owner, false, &["get-property"], dir.path(), || run(
                "printf 'b false'"
            )),
            Some("b false".into())
        );
        assert!(query_bus(owner, true, &[], dir.path(), || run("printf 'b true'")).is_none());
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            query_bus(owner, true, &["call"], dir.path(), || run(
                "printf 'b true'"
            )),
            Some("b true".into())
        );
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(query_bus(owner, true, &[], dir.path(), || run("exit 0")).is_none());
        std::fs::remove_dir(&runtime).unwrap();
        std::fs::write(&runtime, b"file").unwrap();
        assert!(query_bus(owner, true, &[], dir.path(), || run("exit 0")).is_none());
        std::fs::remove_file(&runtime).unwrap();
        std::os::unix::fs::symlink(dir.path(), &runtime).unwrap();
        assert!(query_bus(owner, true, &[], dir.path(), || run("exit 0")).is_none());
        for script in [
            "exit 1",
            "printf '\\377'",
            "i=0; while [ $i -lt 4097 ]; do printf x; i=$((i + 1)); done",
        ] {
            assert!(query_bus(owner, false, &[], dir.path(), || run(script)).is_none());
        }
        assert!(query_bus(owner, false, &[], dir.path(), || Err(
            std::io::Error::other("unavailable")
        ))
        .is_none());
        let system = SystemLoginSignals { owner_uid: owner };
        let _ = system.busctl(false, &["--version"]);
        let _ = system.displays();
    }

    #[test]
    fn incomplete_logind_signals_and_uninitialized_idle_hints_are_away() {
        struct Fake(std::collections::HashMap<&'static str, String>);
        impl LoginSignals for Fake {
            fn busctl(&self, _: bool, args: &[&str]) -> Option<String> {
                let key = match args.first().copied()? {
                    "get-property" => *args.last()?,
                    "call" if args.contains(&"GetSessionByPID") => "session",
                    "call" => "screensaver",
                    _ => return None,
                };
                self.0.get(key).cloned()
            }
            fn displays(&self) -> Option<(bool, Option<bool>)> {
                Some((true, Some(true)))
            }
        }
        let complete = || {
            std::collections::HashMap::from([
                ("session", "o \"/org/freedesktop/login1/session/_1\"".into()),
                (
                    "User",
                    "(uo) 1000 \"/org/freedesktop/login1/user/_1000\"".into(),
                ),
                ("Type", "s \"wayland\"".into()),
                ("Active", "b true".into()),
                ("State", "s \"active\"".into()),
                ("LockedHint", "b false".into()),
                ("screensaver", "b false".into()),
                ("IdleHint", "b false".into()),
                ("IdleSinceHint", "t 1000000".into()),
                ("Remote", "b false".into()),
            ])
        };
        let state = |values| {
            let source =
                LinuxSignalSource::with_backend(Fake(values), 1000, 1, Arc::new(|| Some(true)));
            super::super::classify(&source.sample(), 120)
        };
        assert_eq!(state(complete()), super::super::Presence::Present);
        for field in complete().keys() {
            let mut values = complete();
            values.remove(field);
            assert_eq!(
                state(values),
                super::super::Presence::Away,
                "missing {field}"
            );
        }
        for timestamp in ["t 0", "t 18446744073709551615", "unknown"] {
            let mut values = complete();
            values.insert("IdleSinceHint", timestamp.into());
            assert_eq!(state(values), super::super::Presence::Away);
        }
        let mut idle = complete();
        idle.insert("IdleHint", "b true".into());
        assert_eq!(state(idle), super::super::Presence::Idle);
        for path in [
            "o \"/another/session/_1\"",
            "o \"/org/freedesktop/login1/session/bad.path\"",
            "o invalid",
        ] {
            let mut values = complete();
            values.insert("session", path.into());
            assert_eq!(state(values), super::super::Presence::Away);
        }
        for (field, value) in [
            ("User", "(uo) 1001 \"/user\""),
            ("User", "u 1000"),
            ("Type", "s \"tty\""),
            ("Active", "b false"),
            ("State", "s \"closing\""),
            ("LockedHint", "b true"),
            ("screensaver", "b true"),
        ] {
            let mut values = complete();
            values.insert(field, value.into());
            assert_eq!(state(values), super::super::Presence::Away);
        }
    }
    /// Run on the owner session of a GNOME/KDE Linux workstation:
    /// CARGO_TARGET_DIR=target-w1 cargo test -p kv-platform linux_presence_smoke -- --ignored
    #[test]
    #[ignore = "Requires a logind graphical session, user D-Bus and DRM"]
    fn linux_presence_smoke() {
        let source = LinuxSignalSource::new(unsafe { libc::geteuid() }, Arc::new(|| None));
        assert!(source.sample().graphical_session.is_some());
    }
}
