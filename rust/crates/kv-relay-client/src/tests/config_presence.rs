use std::{cell::Cell, io};

use crate::{config::Config, error::Error};

#[tokio::test]
async fn protected_missing_config_waits_only_after_authoritative_absence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay-client.toml");
    let called = Cell::new(false);
    let binding = Config::load_with_presence_probe(
        &path,
        &path,
        Err(io::ErrorKind::PermissionDenied.into()),
        || async {
            called.set(true);
            Ok(false)
        },
    )
    .await;
    assert!(
        called.get(),
        "denied metadata requires the authenticated helper probe"
    );
    assert!(binding.unwrap().is_none());
}

#[tokio::test]
async fn protected_existing_config_and_probe_failures_still_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay-client.toml");
    std::fs::write(&path, "relay_url='https://relay.example.com'\n").unwrap();
    for probe in [
        Ok(true),
        Err(Error::HelperUntrusted),
        Err(Error::HelperUnavailable),
    ] {
        assert!(Config::load_with_presence_probe(
            &path,
            &path,
            Err(io::ErrorKind::PermissionDenied.into()),
            || async { probe },
        )
        .await
        .is_err());
    }
}

#[tokio::test]
async fn readable_invalid_config_and_other_io_errors_never_use_absence_probe() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay-client.toml");
    for text in [
        "invalid",
        "relay_url='http://public.example.com'",
        "relay_url='https://relay.example.com'\ndevice_id=''\naccount_id='acct'",
    ] {
        std::fs::write(&path, text).unwrap();
        assert!(
            Config::load_with_presence_probe(&path, &path, Ok(()), || async {
                panic!("a parsing error is not absence")
            })
            .await
            .is_err()
        );
    }
    assert!(Config::load_with_presence_probe(
        &path,
        &path,
        Err(io::ErrorKind::InvalidInput.into()),
        || async { panic!("only PermissionDenied can trigger the probe") },
    )
    .await
    .is_err());
    assert!(Config::load_with_presence_probe(
        &path,
        &path,
        Err(io::ErrorKind::NotFound.into()),
        || async { panic!("NotFound is already authoritative") },
    )
    .await
    .unwrap()
    .is_none());
}

#[tokio::test]
async fn a_different_unreadable_path_never_borrows_the_fixed_config_absence_proof() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("custom.toml");
    let fixed = directory.path().join("relay-client.toml");
    assert!(Config::load_with_presence_probe(
        &path,
        &fixed,
        Err(io::ErrorKind::PermissionDenied.into()),
        || async { panic!("the authoritative probe is not for this path") },
    )
    .await
    .is_err());
}
