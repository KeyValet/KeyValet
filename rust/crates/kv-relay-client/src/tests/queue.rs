use super::*;
use crate::tests::harness::envelope;

#[test]
fn lock_errors_and_invalid_sequence_names_fail_closed() {
    #[cfg(not(windows))]
    assert!(matches!(
        lock_error(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        Error::QueueBusy
    ));
    #[cfg(windows)]
    {
        for code in [32, 33] {
            assert!(matches!(
                lock_error(std::io::Error::from_raw_os_error(code)),
                Error::QueueBusy
            ));
        }
        assert!(matches!(
            lock_error(std::io::Error::from_raw_os_error(5)),
            Error::Queue(_)
        ));
    }
    assert!(matches!(
        lock_error(std::io::Error::from(std::io::ErrorKind::NotFound)),
        Error::Queue(_)
    ));
    for name in [
        "bad.json",
        "0000000000000000000x.json",
        "99999999999999999999.json",
    ] {
        assert!(matches!(
            sequence_of(Path::new(name)),
            Err(Error::QueueCorrupt)
        ));
    }
    assert!(matches!(
        sequence_of(Path::new("/")),
        Err(Error::QueueCorrupt)
    ));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        assert!(matches!(
            sequence_of(Path::new(std::ffi::OsStr::from_bytes(b"\xff.json"))),
            Err(Error::QueueCorrupt)
        ));
    }
}

#[tokio::test]
async fn invalid_completions_cannot_remove_or_reorder_committed_messages() {
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    queue
        .append(vec![envelope(1, "grant"), envelope(2, "grant")])
        .await
        .unwrap();
    let path = file_path(directory.path(), 1, "json");
    let original = fs::read(&path).unwrap();
    for (sequence, count) in [(2, 1), (1, 0), (1, 3)] {
        assert!(matches!(
            queue.complete_prefix(sequence, count).await,
            Err(Error::QueueCorrupt)
        ));
        assert_eq!(fs::read(&path).unwrap(), original);
    }
    queue.disk.lock().unwrap().next = u64::MAX;
    assert!(matches!(
        queue.append(vec![envelope(3, "grant")]).await,
        Err(Error::QueueCorrupt)
    ));
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[tokio::test]
async fn poison_and_worker_failure_preserve_the_ciphertext_on_disk() {
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    queue.append(vec![envelope(1, "grant")]).await.unwrap();
    let path = file_path(directory.path(), 1, "json");
    let original = fs::read(&path).unwrap();
    assert!(matches!(
        queue
            .access::<()>(|_| panic!("simulated disk worker failure"))
            .await,
        Err(Error::QueueCorrupt)
    ));
    assert!(matches!(queue.front().await, Err(Error::QueueCorrupt)));
    assert_eq!(fs::read(path).unwrap(), original);
    drop(queue);
    let queue = Queue::open(directory.path()).unwrap();
    assert_eq!(queue.front().await.unwrap().unwrap().sequence, 1);
}

#[test]
fn committed_prefix_wins_over_an_interrupted_rewrite() {
    let directory = tempfile::tempdir().unwrap();
    let path = file_path(directory.path(), 7, "json");
    let original = serde_json::to_vec(&[envelope(1, "grant")]).unwrap();
    fs::write(&path, &original).unwrap();
    let temporary = file_path(directory.path(), 7, "tmp");
    fs::write(&temporary, b"interrupted rewrite").unwrap();
    let _queue = Queue::open(directory.path()).unwrap();
    assert!(!temporary.exists());
    assert_eq!(fs::read(path).unwrap(), original);
}

#[test]
fn startup_preserves_unknown_corrupt_and_oversized_entries() {
    for (name, contents) in [
        ("unexpected.file", b"unknown".to_vec()),
        ("bad.json", b"[]".to_vec()),
        ("00000000000000000001.json", b"[]".to_vec()),
        ("00000000000000000001.json", b"[{}]".to_vec()),
        (
            "00000000000000000001.json",
            vec![b' '; kv_ipc::MAX_LINE_BYTES + 1],
        ),
        ("00000000000000000001.tmp", b"partial write".to_vec()),
        (
            "18446744073709551615.json",
            serde_json::to_vec(&[envelope(1, "grant")]).unwrap(),
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(name);
        fs::write(&path, &contents).unwrap();
        assert!(matches!(
            Queue::open(directory.path()),
            Err(Error::QueueCorrupt)
        ));
        assert_eq!(fs::read(path).unwrap(), contents);
    }
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("queue.lock")).unwrap();
    assert!(matches!(
        Queue::open(directory.path()),
        Err(Error::Queue(_))
    ));
}

#[tokio::test]
async fn oversized_batch_is_rejected_before_any_ciphertext_file_is_created() {
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(envelope(1, "grant").0.get()).unwrap();
    value["ct"] = serde_json::json!("A".repeat(75 * 1024));
    let large: Envelope = serde_json::from_value(value).unwrap();
    let oversized = vec![large; 14];
    assert!(matches!(
        write_batch(directory.path(), 1, &oversized),
        Err(Error::HelperProtocol)
    ));
    assert!(matches!(
        queue.append(oversized).await,
        Err(Error::HelperProtocol)
    ));
    assert!(queue.front().await.unwrap().is_none());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}
