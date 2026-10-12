use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(crate) fn bounded_output(
    command: &mut Command,
    limit: usize,
    timeout: Duration,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut child = Running(command.stdout(Stdio::piped()).spawn()?);
    let mut stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing subprocess output"))?;
    nonblocking(stdout.as_raw_fd())?;
    read_output(&mut stdout, || child.0.try_wait(), limit, timeout)
}

fn nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_output(
    stdout: &mut impl Read,
    mut wait: impl FnMut() -> io::Result<Option<ExitStatus>>,
    limit: usize,
    timeout: Duration,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let deadline = Instant::now() + timeout;
    let mut output = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0u8; 1024]);
    let mut eof = false;
    let mut status = None;
    loop {
        if !eof {
            match stdout.read(buffer.as_mut()) {
                Ok(0) => eof = true,
                Ok(count) => {
                    if count > limit.saturating_sub(output.len()) {
                        return Err(io::Error::other("subprocess output too large"));
                    }
                    output.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        if status.is_none() {
            status = wait()?;
        }
        if let Some(status) = status.filter(|_| eof) {
            return if status.success() {
                Ok(output)
            } else {
                Err(io::Error::other("subprocess failed"))
            };
        }
        // The deadline also applies after the child exits with a pipe still held open.
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "subprocess timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn command(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script])
            .env_clear()
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[test]
    fn bounded_output_accepts_exact_limit_and_rejects_failure_or_extra_bytes() {
        assert!(
            bounded_output(&mut command("printf abcd"), 4, Duration::from_secs(2))
                .unwrap()
                .as_slice()
                == b"abcd"
        );
        assert!(bounded_output(&mut command("printf abcde"), 4, Duration::from_secs(2)).is_err());
        assert!(bounded_output(&mut command("exit 1"), 4, Duration::from_secs(2)).is_err());
        assert!(
            bounded_output(&mut command("exit 0"), 0, Duration::from_secs(2))
                .unwrap()
                .is_empty()
        );
        assert!(bounded_output(
            &mut Command::new("/nonexistent-keyvalet-test-command"),
            4,
            Duration::from_secs(2)
        )
        .is_err());
    }

    #[test]
    fn deadline_covers_silent_processes_and_output_after_parent_exit() {
        for script in ["exec /bin/sleep 5", "/bin/sleep 0.5 & exit 0"] {
            let started = Instant::now();
            let error =
                bounded_output(&mut command(script), 4, Duration::from_millis(30)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }

    #[test]
    fn polling_retries_transient_reads_and_propagates_io_errors() {
        struct FaultThen {
            error: Option<io::ErrorKind>,
            bytes: io::Cursor<Vec<u8>>,
        }
        impl Read for FaultThen {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if let Some(error) = self.error.take() {
                    return Err(io::Error::from(error));
                }
                self.bytes.read(buffer)
            }
        }
        assert!(nonblocking(-1).is_err());
        for kind in [
            io::ErrorKind::Interrupted,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Other,
        ] {
            let mut reader = FaultThen {
                error: Some(kind),
                bytes: io::Cursor::new(b"abcd".to_vec()),
            };
            let result = read_output(
                &mut reader,
                || Ok(Some(ExitStatus::from_raw(0))),
                4,
                Duration::from_secs(2),
            );
            if kind == io::ErrorKind::Other {
                assert_eq!(result.unwrap_err().kind(), kind);
            } else {
                assert_eq!(result.unwrap().as_slice(), b"abcd");
            }
        }
        let error = read_output(
            &mut io::empty(),
            || Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            4,
            Duration::from_secs(2),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let mut checks = 0;
        let output = read_output(
            &mut io::empty(),
            || {
                checks += 1;
                Ok((checks == 3).then(|| ExitStatus::from_raw(0)))
            },
            4,
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(output.is_empty());
        assert_eq!(checks, 3);
    }
}
