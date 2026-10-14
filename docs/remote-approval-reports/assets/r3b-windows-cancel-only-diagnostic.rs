
#[cfg(test)]
mod r3b_cancel_only_diagnostic {
    use super::*;
    use std::path::PathBuf;
    use std::time::Instant;

    #[test]
    #[ignore = "Explicit owner desktop cancellation diagnostic; no credentials or installed worker"]
    fn cancellation_started_on_desktop() {
        assert_eq!(std::env::var("R3B_CANCEL_ONLY_OPT_IN").as_deref(), Ok("1"));
        let output = PathBuf::from(std::env::var_os("R3B_CANCEL_ONLY_OUTPUT").unwrap());
        assert!(output.is_dir());
        let publish = |name: &str, value: &Value| {
            std::fs::write(output.join(format!("{name}.json")), serde_json::to_vec(value).unwrap()).unwrap();
        };
        unsafe {
            windows::Win32::System::WinRT::RoInitialize(
                windows::Win32::System::WinRT::RO_INIT_MULTITHREADED,
            ).unwrap();
        }
        let _apartment = CreationGuard::new(|| unsafe {
            windows::Win32::System::WinRT::RoUninitialize();
        });
        let supported = KeyCredentialManager::IsSupportedAsync()
            .and_then(|operation| wait(operation, &Budget::new())).unwrap();
        publish("progress", &json!({"stage":"create_approve","supported":supported}));
        assert!(supported);
        let timer = Instant::now();
        let metadata = create(&Budget::new()).unwrap();
        let create_ms = timer.elapsed().as_secs_f64() * 1000.0;
        publish("key-metadata", &metadata);
        let name = metadata["key_name"].as_str().unwrap().to_owned();
        let cleanup = CreationGuard::new(|| { let _ = delete(&name); });
        publish("progress", &json!({"stage":"desktop_cancel_instructions","create_ms":create_ms}));
        // This separate diagnostic purpose dialog consumes no production signing budget.
        let ready = kv_platform::windows::confirm_with_timeout(
            "接下来只测取消。请把手指移开读头，在新的 Windows Hello 安全窗口点“取消”，不要输入 PIN。",
            "开始取消测试",
            std::time::Duration::from_secs(300),
        );
        assert!(ready, "Operator did not start the native cancellation diagnostic");
        publish("progress", &json!({"stage":"cancel_sign"}));
        let timer = Instant::now();
        let result = sign(&metadata, &rand::random::<[u8;32]>(), &Budget::new());
        let sign_ms = timer.elapsed().as_secs_f64() * 1000.0;
        let status = SIGN_STATUS.with(std::cell::Cell::get);
        let user_cancelled = result.is_err() && status == Some(KeyCredentialStatus::UserCanceled.0);
        publish("sign-result", &json!({"status":status,"user_cancelled":user_cancelled,
            "signature_returned":result.is_ok(),"sign_ms":sign_ms,"create_ms":create_ms,"supported":supported}));
        let deleted = delete(&name);
        let reopened = KeyCredentialManager::OpenAsync(&HSTRING::from(&name))
            .and_then(|operation| wait(operation, &Budget::new()));
        let missing = reopened.as_ref().ok().and_then(|value| value.Status().ok())
            == Some(KeyCredentialStatus::NotFound);
        publish("cleanup-result", &json!({"delete_async_succeeded":deleted.is_ok(),"open_async_not_found":missing}));
        if deleted.is_ok() && missing { cleanup.commit(); }
        publish("progress", &json!({"stage":"complete","passed":user_cancelled && deleted.is_ok() && missing}));
        assert!(user_cancelled, "An actual UserCanceled(3) result is required");
        assert!(deleted.is_ok() && missing, "Hello deletion must be independently verified");
    }
}
