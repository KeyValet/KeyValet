//! Temporary ignored native acceptance tests; no vault, IPC, or protection bypass.
use super::*;
use std::time::Duration;

fn apartment() -> CreationGuard<impl FnOnce()> {
    unsafe {
        windows::Win32::System::WinRT::RoInitialize(
            windows::Win32::System::WinRT::RO_INIT_MULTITHREADED,
        )
        .unwrap();
    }
    CreationGuard::new(|| unsafe {
        windows::Win32::System::WinRT::RoUninitialize();
    })
}

fn cleanup_checked(metadata: &Value) {
    let name = metadata["key_name"].as_str().unwrap();
    delete(name).expect("DeleteAsync must finish successfully");
    let result = KeyCredentialManager::OpenAsync(&HSTRING::from(name))
        .and_then(|op| wait(op, &Budget::new()))
        .expect("OpenAsync must complete after deletion");
    assert_eq!(result.Status().unwrap(), KeyCredentialStatus::NotFound);
    eprintln!("PHYSICAL_ACCEPTANCE cleanup=deleted_and_not_found");
}

#[test]
#[ignore = "Requires Windows 11 owner desktop, Hello PIN/fingerprint and user interaction"]
fn remote_hello_repeat_signatures() {
    let _apartment = apartment();
    eprintln!("PHYSICAL_ACCEPTANCE stage=create_approve");
    let metadata = create(&Budget::new()).unwrap();
    let name = metadata["key_name"].as_str().unwrap().to_owned();
    let cleanup = CreationGuard::new(|| {
        let _ = delete(&name);
    });
    for message in [
        b"KeyValet physical Strong decision fixture 1".as_slice(),
        b"KeyValet physical Strong decision fixture 2".as_slice(),
    ] {
        eprintln!("PHYSICAL_ACCEPTANCE stage=sign_approve");
        // Production sign() pins the public key and verifies RSA-2048 / RS256.
        assert_eq!(sign(&metadata, message, &Budget::new()).unwrap().len(), 256);
        eprintln!("PHYSICAL_ACCEPTANCE signature=verified bytes=256");
    }
    cleanup_checked(&metadata);
    cleanup.commit();
}

#[test]
#[ignore = "Requires Windows 11 owner desktop: approve creation, then cancel the sign prompt"]
fn remote_hello_sign_cancellation() {
    let _apartment = apartment();
    eprintln!("PHYSICAL_ACCEPTANCE stage=create_approve");
    let metadata = create(&Budget::new()).unwrap();
    let name = metadata["key_name"].as_str().unwrap().to_owned();
    let cleanup = CreationGuard::new(|| {
        let _ = delete(&name);
    });
    // The supervisor sends cancellation instructions only after this log confirms creation.
    // This opt-in test checkpoint does not change any production Hello request budget.
    let gate = std::env::var_os("KEYVALET_PHYSICAL_CANCEL_GATE")
        .expect("Set a fresh checkpoint path for this interactive acceptance test");
    let gate = std::path::PathBuf::from(gate);
    assert!(!gate.exists(), "Cancellation checkpoint must initially be absent");
    eprintln!("PHYSICAL_ACCEPTANCE stage=created_waiting_for_cancel_instructions");
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    while !gate.exists() {
        assert!(std::time::Instant::now() < deadline, "Acceptance checkpoint expired");
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("PHYSICAL_ACCEPTANCE stage=sign_cancel");
    assert!(matches!(
        sign(&metadata, b"KeyValet physical cancellation fixture", &Budget::new()),
        Err(DeviceKeyError::OperationFailed)
    ));
    eprintln!("PHYSICAL_ACCEPTANCE signing=rejected");
    cleanup_checked(&metadata);
    cleanup.commit();
    std::fs::remove_file(&gate).unwrap();
}
