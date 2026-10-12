#[cfg(not(windows))]
#[test]
fn unsupported_platform_entry_preserves_the_existing_exit_status() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kv-agent"))
        .arg("--help")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("Windows 11"));
}
