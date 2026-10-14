use super::*;
use crate::remote::bootstrap::{Environment, Options};
use crate::remote::pairing_relay::RelayApi;
use crate::remote::recovery::{Enrollment, Recovery};
use kv_core::remote::relay::{RegisterDeviceRequest, RegisterDeviceResponse};

#[tokio::test]
async fn helper_recovery_persists_replacement_before_enrollment_and_resumes_a_lost_reply() {
    let (url, server) = kv_server::spawn_test_relay();
    let h = Harness::new();
    let relay = RelayApi::new(url.as_str()).unwrap();
    let old: RegisterDeviceResponse = relay
        .post(
            "v1/devices",
            &RegisterDeviceRequest {
                device: h.helper.local.clone(),
                push_token: Optional::Missing,
            },
            None,
        )
        .await
        .unwrap();
    let code = old.recovery_code.as_value().unwrap().clone();
    let recovery = Arc::new(
        Recovery::new(kv_ipc::remote::AccountRecoverIntent {
            account_id: old.account_id.clone(),
            recovery_code: code.clone(),
            relay_url: url.to_string(),
            software: true,
        })
        .unwrap(),
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote");
    let enrolling = recovery.clone();
    let task = tokio::task::spawn_blocking(move || {
        let keys = crate::remote::platform_keys::SoftwareKeys;
        let master = crate::remote::metadata_master::IdentityMaster { keys: &keys };
        let registrar = Enrollment {
            recovery: &enrolling,
            factory: &keys,
        };
        crate::remote::bootstrap::open_registered(
            Options {
                path: &path,
                initialize: Some(("", "replacement", "test-recovery-passphrase-42", Os::Linux)),
                config: ApprovalConfig::default(),
            },
            Environment {
                master: &master,
                factory: &keys,
                runner: h.runner.clone(),
                presence: h.presence.clone(),
                clock: h.clock.clone(),
            },
            &registrar,
        )
    });
    let (backend, response) = task.await.unwrap().unwrap();
    let response = response.unwrap();
    assert_eq!(response.account_id, old.account_id);
    let replacement = response.recovery_code.as_value().unwrap().clone();
    assert_ne!(replacement, code);
    assert_eq!(
        backend
            .metadata
            .authenticated_metadata("remote_recovery_prepared")
            .unwrap()
            .unwrap()["recovery_code"],
        replacement
    );
    // Publish/reply may be interrupted after relay commit. The durable DK proves the same account
    // and the prepared replacement survives without consuming a second recovery code.
    let original = backend.helper.clone();
    let vault = backend.metadata.clone();
    let resumed = tokio::task::spawn_blocking(move || {
        recovery.enroll(&original.local, original.services.identity.clone(), &vault)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(resumed, response);
    assert!(!server.logs().join("\n").contains(&code));
    assert!(!server.logs().join("\n").contains(&replacement));
    for entry in std::fs::read_dir(directory.path().join("remote")).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(path).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains(&replacement));
            assert!(!String::from_utf8_lossy(&bytes).contains(&code));
        }
    }
    server.shutdown().await;
}

#[tokio::test]
async fn rejected_recovery_preserves_unregistered_keys_for_an_owner_retry() {
    let (url, server) = kv_server::spawn_test_relay();
    let h = Harness::new();
    let relay = RelayApi::new(url.as_str()).unwrap();
    let old: RegisterDeviceResponse = relay
        .post(
            "v1/devices",
            &RegisterDeviceRequest {
                device: h.helper.local.clone(),
                push_token: Optional::Missing,
            },
            None,
        )
        .await
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote");
    let wrong = Recovery::new(kv_ipc::remote::AccountRecoverIntent {
        account_id: old.account_id.clone(),
        recovery_code: kv_core::remote::keys::encode_b64(&[42; 32]),
        relay_url: url.to_string(),
        software: true,
    })
    .unwrap();
    let creating = path.clone();
    let backend = tokio::task::spawn_blocking(move || {
        let keys = crate::remote::platform_keys::SoftwareKeys;
        let master = crate::remote::metadata_master::IdentityMaster { keys: &keys };
        let env = || Environment {
            master: &master,
            factory: &keys,
            runner: h.runner.clone(),
            presence: h.presence.clone(),
            clock: h.clock.clone(),
        };
        let registrar = Enrollment {
            recovery: &wrong,
            factory: &keys,
        };
        assert!(crate::remote::bootstrap::open_registered(
            Options {
                path: &creating,
                initialize: Some(("", "replacement", "test-recovery-passphrase-42", Os::Linux)),
                config: ApprovalConfig::default()
            },
            env(),
            &registrar
        )
        .is_err());
        crate::remote::bootstrap::open(
            Options {
                path: &creating,
                initialize: None,
                config: ApprovalConfig::default(),
            },
            env(),
        )
        .unwrap()
    })
    .await
    .unwrap();
    let local = backend.helper.local.clone();
    let prepared = backend
        .metadata
        .authenticated_metadata("remote_recovery_prepared")
        .unwrap()
        .unwrap();
    let recovery = Recovery::new(kv_ipc::remote::AccountRecoverIntent {
        account_id: old.account_id,
        recovery_code: old.recovery_code.as_value().unwrap().clone(),
        relay_url: url.to_string(),
        software: true,
    })
    .unwrap();
    let result = tokio::task::spawn_blocking(move || {
        assert!(backend.helper.account.starts_with("unregistered:"));
        recovery.enroll(
            &backend.helper.local,
            backend.helper.services.identity.clone(),
            &backend.metadata,
        )
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.device_id, local.device_id);
    assert_eq!(
        result.recovery_code.as_value().unwrap(),
        prepared["recovery_code"].as_str().unwrap()
    );
    server.shutdown().await;
}
