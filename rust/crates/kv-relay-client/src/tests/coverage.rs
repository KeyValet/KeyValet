//! Public entry points and hostile input cases that do not need native service installation.

use std::{ffi::OsString, io, time::Duration};

use super::*;
use crate::{app, envelope::MAX_ENVELOPE_BYTES, platform};

#[test]
fn command_validation_rejects_extra_arguments() {
    assert!(matches!(app::parse(&[]), Ok(app::Action::Run)));
    for help in ["--help", "-h"] {
        assert!(matches!(
            app::parse(&[OsString::from(help)]),
            Ok(app::Action::Help)
        ));
        assert!(matches!(
            app::parse(&[OsString::from(help), OsString::from("extra")]),
            Err(Error::Config)
        ));
    }
    assert!(matches!(
        app::parse(&[OsString::from("--config")]),
        Err(Error::Config)
    ));
    #[cfg(windows)]
    for (arguments, expected) in [
        (vec!["--service"], "service"),
        (vec!["service", "install"], "install"),
        (vec!["service", "uninstall"], "uninstall"),
    ] {
        let arguments: Vec<_> = arguments.into_iter().map(OsString::from).collect();
        assert!(matches!(
            (app::parse(&arguments).unwrap(), expected),
            (app::Action::Service, "service")
                | (app::Action::Install, "install")
                | (app::Action::Uninstall, "uninstall")
        ));
    }
}

#[tokio::test]
async fn daemon_configuration_uses_repo_independent_paths_and_reports_startup_errors() {
    let helper = FakeHelper::start(events(), false).await;
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("relay-client.toml");
    let queue = directory.path().join("queue");
    let (_shutdown, receiver) = tokio::sync::watch::channel(true);
    assert!(matches!(
        app::run(&config, &queue, helper.client(false), receiver.clone()).await,
        Ok(())
    ));
    assert!(!queue.exists());
    fs::write(
        &config,
        "relay_url='http://127.0.0.1:1/'\ndevice_id='dev'\naccount_id='acct'\n",
    )
    .unwrap();
    fs::write(&queue, b"not a directory").unwrap();
    assert!(matches!(
        app::run(&config, &queue, helper.client(false), receiver.clone()).await,
        Err(Error::Queue(_))
    ));
    fs::remove_file(&queue).unwrap();
    app::run(&config, &queue, helper.client(false), receiver)
        .await
        .unwrap();
    let data = helper.data.lock().unwrap();
    // Shutdown status is best effort; a cancelled Windows pipe exchange may still be busy.
    assert!(data.statuses.iter().all(|status| !status.connected));
    assert!(data.signed.is_empty());
    assert!(queue.join("queue.lock").is_file());
}

#[test]
fn platform_layout_derivation_does_not_read_installed_files() {
    let config = platform::config_path().unwrap();
    let queue = platform::queue_path().unwrap();
    let endpoint = platform::helper_endpoint();
    let _ = helper::Helper::new();
    assert!(config.is_absolute());
    assert!(queue.is_absolute());
    assert!(config.ends_with("relay-client.toml"));
    #[cfg(target_os = "macos")]
    {
        assert!(config.ends_with("Library/Application Support/KeyValet/relay-client.toml"));
        assert_eq!(queue, config.with_file_name("relay-queue"));
        assert_eq!(
            endpoint,
            std::path::Path::new(kv_platform::paths::HELPER_SOCKET)
        );
    }
    #[cfg(target_os = "linux")]
    {
        assert_eq!(
            config,
            std::path::Path::new("/etc/keyvalet/relay-client.toml")
        );
        assert_eq!(queue, std::path::Path::new("/var/lib/keyvalet-relay/queue"));
        assert!(endpoint.ends_with("keyvalet/relay.sock"));
    }
    #[cfg(windows)]
    {
        assert_eq!(platform::service_name(), "KeyValetRelay");
        assert_eq!(endpoint, std::path::Path::new(r"\\.\pipe\keyvalet-relay"));
        assert!(queue.ends_with("KeyValet/Relay/queue"));
    }
    #[cfg(any(target_os = "macos", windows))]
    platform::verify_runtime_account().unwrap();
}

#[test]
fn errors_only_display_local_categories_and_io_kinds() {
    for (error, text) in [
        (Error::Config, "invalid_relay_configuration"),
        (Error::HelperUnavailable, "helper_unavailable"),
        (Error::HelperUntrusted, "helper_untrusted"),
        (Error::HelperProtocol, "helper_protocol_error"),
        (Error::HelperRejected, "helper_rejected_request"),
        (Error::IdentityUnavailable, "identity_key_unavailable"),
        (Error::Network, "relay_unreachable"),
        (Error::RelayProtocol, "relay_protocol_error"),
        (Error::QueueCorrupt, "queue_corrupt"),
        (Error::QueueBusy, "queue_in_use"),
    ] {
        assert_eq!(error.to_string(), text);
        assert!(error.retry_after().is_none());
    }
    let error = Error::from(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "secret path or body",
    ));
    assert_eq!(error.to_string(), "queue_io_error (PermissionDenied)");
    let error = Error::RelayHttp {
        status: 429,
        retry_after: Some(Duration::from_secs(3)),
    };
    assert_eq!(error.to_string(), "relay_http_429");
    assert_eq!(error.retry_after(), Some(Duration::from_secs(3)));
}

#[test]
fn queue_envelope_checks_framing_without_crypto_or_expiry_policy() {
    let original: Value = serde_json::from_str(envelope(1, "grant").0.get()).unwrap();
    for (field, invalid) in [
        ("id", json!("")),
        ("type", json!("")),
        ("account", json!("")),
        ("from", json!("")),
        ("to", json!("")),
        ("enc", json!("")),
        ("ct", json!("plaintext with spaces")),
        ("sig", json!("AA==")),
        ("id", Value::Null),
        ("exp", json!("invalid")),
    ] {
        let mut value = original.clone();
        value[field] = invalid;
        let envelope: Envelope = serde_json::from_value(value).unwrap();
        assert!(matches!(
            envelope.validate_for_queue(),
            Err(Error::HelperProtocol)
        ));
    }
    let mut oversized = original.clone();
    oversized["ct"] = json!("A".repeat(MAX_ENVELOPE_BYTES));
    let oversized: Envelope = serde_json::from_value(oversized).unwrap();
    assert!(matches!(
        oversized.validate_for_queue(),
        Err(Error::HelperProtocol)
    ));
    let mut future = original;
    future["v"] = json!(999);
    future["exp"] = json!(0);
    future["enc"] = json!("a-z_9");
    let future: Envelope = serde_json::from_value(future).unwrap();
    future.validate_for_queue().unwrap();
}

#[test]
fn configuration_handles_io_utf8_and_url_edge_cases() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config");
    assert!(matches!(Config::load(&path), Err(Error::Config)));
    fs::write(&path, [0xff, 0xfe]).unwrap();
    assert!(matches!(Config::load(&path), Err(Error::Config)));
    for url in ["http://[::1]:80/", "https://relay.example.com/base/"] {
        let config = Config {
            relay_url: url.into(),
            device_id: "dev".into(),
            account_id: "acct".into(),
        };
        assert_eq!(
            config.base_url().unwrap().as_str(),
            url.replace(":80/", "/")
        );
    }
    for url in [
        "invalid",
        "file:///tmp/relay",
        "https://relay.example.com/#fragment",
        "http://localhost/",
    ] {
        let config = Config {
            relay_url: url.into(),
            device_id: "dev".into(),
            account_id: "acct".into(),
        };
        assert!(matches!(config.base_url(), Err(Error::Config)));
    }
    for id in ["x".repeat(257), "dev\ncontrol".into()] {
        fs::write(
            &path,
            format!(
                "relay_url='https://relay.example.com/'\ndevice_id={}\naccount_id='acct'",
                serde_json::to_string(&id).unwrap()
            ),
        )
        .unwrap();
        assert!(matches!(Config::load(&path), Err(Error::Config)));
    }
}

#[test]
fn retry_after_is_bounded_and_tolerates_untrusted_headers() {
    use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
    let mut headers = HeaderMap::new();
    assert!(transport::retry_after(&headers).is_none());
    headers.insert(RETRY_AFTER, u64::MAX.to_string().parse().unwrap());
    assert_eq!(
        transport::retry_after(&headers),
        Some(Duration::from_secs(86400))
    );
    headers.insert(
        RETRY_AFTER,
        "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap(),
    );
    assert_eq!(transport::retry_after(&headers), Some(Duration::ZERO));
    headers.insert(RETRY_AFTER, HeaderValue::from_bytes(&[0xff]).unwrap());
    assert!(transport::retry_after(&headers).is_none());
}
