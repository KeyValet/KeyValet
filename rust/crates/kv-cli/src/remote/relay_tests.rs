use super::*;

#[test]
fn server_installation_keeps_client_state_separate() {
    let directory = tempfile::tempdir().unwrap();
    let installed = install(
        directory.path(),
        "127.0.0.1:8787",
        Path::new("/var/lib/keyvalet-relay-server"),
        "https://relay.example.com",
    )
    .unwrap();
    let unit = std::fs::read_to_string(installed.service).unwrap();
    assert!(unit.contains("StateDirectory=keyvalet-relay-server\n"));
    assert!(unit.contains("--data \"/var/lib/keyvalet-relay-server\""));
    assert!(!unit.contains("StateDirectory=keyvalet-relay\n"));
    for data in ["/var/lib/keyvalet-relay", "/var/lib/keyvalet-relay/queue"] {
        let rejected = tempfile::tempdir().unwrap();
        assert!(install(
            rejected.path(),
            "127.0.0.1:8787",
            Path::new(data),
            "https://relay.example.com",
        )
        .is_err());
        assert!(!rejected.path().join("etc").exists());
    }
}

#[test]
fn atomic_write_collision_preserves_another_writers_file() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("config");
    let temporary = directory.path().join("temporary");
    std::fs::write(&target, "original config").unwrap();
    std::fs::write(&temporary, "another writer").unwrap();
    assert!(write_file(&target, "replacement", &temporary).is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "original config");
    assert_eq!(
        std::fs::read_to_string(&temporary).unwrap(),
        "another writer"
    );
}

#[test]
fn failed_rename_cleans_only_its_own_temporary_file() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("directory");
    let temporary = directory.path().join("temporary");
    std::fs::create_dir(&target).unwrap();
    assert!(write_file(&target, "replacement", &temporary).is_err());
    assert!(target.is_dir());
    assert!(!temporary.exists());
}

#[cfg(unix)]
#[test]
fn non_utf8_data_paths_are_rejected_before_writing_assets() {
    use std::os::unix::ffi::OsStringExt;
    let directory = tempfile::tempdir().unwrap();
    let data = PathBuf::from(std::ffi::OsString::from_vec(b"/data/\xff".to_vec()));
    assert_eq!(
        install(
            directory.path(),
            "127.0.0.1:8787",
            &data,
            "https://relay.example.com"
        )
        .unwrap_err()
        .exit_code(),
        2
    );
    assert!(!directory.path().join("etc").exists());
}
