#![cfg(target_os = "macos")]

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};

#[test]
fn malformed_cli_input_has_no_binary_output_and_needs_no_installed_keyvalet() {
    for input in [b"!".as_slice(), b"{}", b""] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kv-touchid"))
            .arg("--device-key")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn device_key_dispatch_preserves_the_existing_enclave_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_kv-touchid"))
        .args(["--enclave", "invalid-operation"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn bridge_refuses_a_terminal_before_reading_or_using_hardware() {
    let mut master = -1;
    let mut slave = -1;
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    let mut master = unsafe { std::fs::File::from_raw_fd(master) };
    let slave = unsafe { std::fs::File::from_raw_fd(slave) };
    let status = Command::new(env!("CARGO_BIN_EXE_kv-touchid"))
        .arg("--device-key")
        .stdin(Stdio::null())
        .stdout(Stdio::from(slave))
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
    let fd = master.as_raw_fd();
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) },
        0
    );
    let mut byte = [0; 1];
    assert!(matches!(master.read(&mut byte), Ok(0) | Err(_)));
}
