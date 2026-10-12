use kv_platform::presence::windows::WindowsSignalSource;
use kv_platform::presence::{unix_seconds, DebouncedPresence, IDLE_THRESHOLD_SECONDS};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::core::Interface;
use windows::Security::Credentials::KeyCredentialManager;
use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};

pub fn hello_available() -> Option<bool> {
    unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.ok()?;
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe {
                RoUninitialize();
            }
        }
    }
    let _apartment = Apartment;
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
