use kv_platform::presence::windows::WindowsSignalSource;
use kv_platform::presence::{unix_seconds, DebouncedPresence, IDLE_THRESHOLD_SECONDS};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::core::Interface;
use windows::Security::Credentials::KeyCredentialManager;
use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};

struct Apartment;
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe {
            RoUninitialize();
        }
    }
}
thread_local! {
    static APARTMENT: super::windows_hello::ThreadApartment<Apartment> = const {
        super::windows_hello::ThreadApartment::new()
    };
}

/// Retain this thread's WinRT apartment while SDK activation factories can be reused.
/// Each successful initialization is balanced at thread exit, not between requests.
pub fn with_winrt<T>(query: impl FnOnce() -> T) -> windows::core::Result<T> {
    APARTMENT.with(|apartment| {
        apartment.query(
            || unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.map(|_| Apartment),
            query,
        )
    })
}

pub fn hello_available() -> Option<bool> {
    with_winrt(query_hello_available).ok().flatten()
}

fn query_hello_available() -> Option<bool> {
    let operation = KeyCredentialManager::IsSupportedAsync().ok()?;
    let info = operation.cast::<windows_future::IAsyncInfo>().ok()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while info.Status().ok()? == windows_future::AsyncStatus::Started {
        if Instant::now() >= deadline {
            let _ = info.Cancel();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    operation.GetResults().ok()
}

/// Construct in the unelevated owner session; the reporter owns the authenticated IPC sink.
pub fn probe(owner_sid: Vec<u8>) -> DebouncedPresence<WindowsSignalSource> {
    DebouncedPresence::new(
        WindowsSignalSource::new(owner_sid, Arc::new(hello_available)),
        IDLE_THRESHOLD_SECONDS,
        unix_seconds(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kv_ipc::remote::PresenceProbe;

    /// Run in the unelevated owner's desktop, lock and unlock during the capture.
    #[test]
    #[ignore = "Requires a real Windows desktop and owner lock/unlock"]
    fn windows_presence_native_transitions() {
        let owner = kv_platform::peer::self_identity().unwrap();
        let probe = probe(owner.sid);
        let output = std::path::PathBuf::from(
            std::env::var_os("R3B_PRESENCE_REPORT").expect("set a private report path"),
        );
        let duration = std::env::var("R3B_PRESENCE_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(120)
            .clamp(10, 300);
        let start = Instant::now();
        let mut samples = Vec::new();
        while start.elapsed() < Duration::from_secs(duration) {
            let state = probe.state();
            samples.push(
                serde_json::json!({"elapsed_ms":start.elapsed().as_millis(),"observation":state}),
            );
            std::fs::write(
                &output,
                serde_json::to_vec_pretty(&serde_json::json!({
                    "complete":false,"samples":samples,
                }))
                .unwrap(),
            )
            .unwrap();
            std::thread::sleep(Duration::from_millis(500));
        }
        let mut saw_present = false;
        let mut saw_locked_away = false;
        let mut saw_unlocked_present = false;
        for sample in &samples {
            let state = &sample["observation"];
            if state["state"] == "present" {
                if saw_locked_away {
                    saw_unlocked_present = true;
                }
                saw_present = true;
            }
            if saw_present && state["state"] == "away" && state["signals"]["screen_locked"] == true
            {
                saw_locked_away = true;
            }
        }
        let passed = saw_present && saw_locked_away && saw_unlocked_present;
        std::fs::write(
            &output,
            serde_json::to_vec_pretty(&serde_json::json!({
                "complete":true,"passed":passed,"samples":samples,
                "saw_present":saw_present,"saw_locked_away":saw_locked_away,
                "saw_unlocked_present":saw_unlocked_present,
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(
            passed,
            "missing native present -> locked away -> unlocked present transition"
        );
    }
}
