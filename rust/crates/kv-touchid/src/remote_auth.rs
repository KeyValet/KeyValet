//! Typed LocalAuthentication facts for the signed, per-user remote agent.
use serde_json::{json, Value};
use std::io::{self, Read};
use std::time::{Duration, Instant};

pub struct ChildResult {
    pub code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
}

fn outcome(success: bool, code: Option<isize>) -> &'static str {
    if success {
        "approved"
    } else {
        match code {
            // AuthenticationFailed is a biometric failure, not a refusal.
            Some(-1 | -8) => "failed",
            // UserCancel, UserFallback, SystemCancel, AppCancel.
            Some(-2 | -3 | -4 | -9) => "cancelled",
            Some(-7..=-5) => "unsupported",
            _ => "unavailable",
        }
    }
}

pub fn reply(input: &Value, run: impl FnOnce(&str, &str) -> io::Result<ChildResult>) -> Value {
    let id = input["id"].as_u64().unwrap_or(0);
    let result = (|| {
        let reason = input["reason"].as_str()?;
        let cancel = input["cancel"].as_str()?;
        if reason.len() > 8192 || cancel.len() > 512 {
            return None;
        }
        let child = run(reason, cancel).ok()?;
        if child.timed_out {
            return Some("timeout");
        }
        if child.code != Some(0) || child.stdout.len() > 1024 {
            return None;
        }
        let value: Value = serde_json::from_slice(&child.stdout).ok()?;
        match value["outcome"].as_str()? {
            "approved" => Some("approved"),
            "cancelled" => Some("cancelled"),
            "failed" => Some("failed"),
            "unsupported" => Some("unsupported"),
            "unavailable" => Some("unavailable"),
            _ => None,
        }
    })();
    json!({"id":id,"outcome":result.unwrap_or("unavailable")})
}

pub fn child(reason: &str, cancel: &str) -> io::Result<ChildResult> {
    use kv_platform::{paths::TOUCHID_BIN, trust::untrusted_reason};
    use std::path::Path;
    use std::process::{Command, Stdio};
    // This check belongs to the real runner, not the injected reply logic.
    if untrusted_reason(Path::new(TOUCHID_BIN)).is_some() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut process = Command::new(TOUCHID_BIN)
        .args(["--remote-authenticate", reason, cancel])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut timed_out = false;
    let code = loop {
        match process.try_wait()? {
            Some(status) => break status.code(),
            None if Instant::now() >= deadline => {
                timed_out = true;
                let _ = process.kill();
                let _ = process.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let mut stdout = Vec::new();
    if let Some(output) = process.stdout.take() {
        output.take(1025).read_to_end(&mut stdout)?;
    }
    Ok(ChildResult {
        code,
        timed_out,
        stdout,
    })
}

pub fn authenticate() {
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    let args: Vec<String> = std::env::args().skip(2).take(2).collect();
    let result = if let [reason, cancel] = args.as_slice() {
        let context = unsafe { LAContext::new() };
        unsafe { context.setLocalizedCancelTitle(Some(&NSString::from_str(cancel))) };
        let policy = LAPolicy::DeviceOwnerAuthentication;
        if unsafe { context.canEvaluatePolicy_error(policy) }.is_err() {
            "unsupported"
        } else {
            let (sender, receiver) = std::sync::mpsc::channel();
            let callback =
                block2::RcBlock::new(move |success: objc2::runtime::Bool, error: *mut NSError| {
                    let code = unsafe { error.as_ref() }.map(|error| error.code());
                    let _ = sender.send(outcome(success.as_bool(), code));
                });
            unsafe {
                context.evaluatePolicy_localizedReason_reply(
                    policy,
                    &NSString::from_str(reason),
                    &callback,
                )
            };
            let result = receiver
                .recv_timeout(Duration::from_secs(115))
                .unwrap_or("timeout");
            unsafe { context.invalidate() };
            result
        }
    } else {
        "unavailable"
    };
    println!("{}", json!({"outcome":result}));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn r3a_native_auth_facts_and_child_failures_never_become_a_denial() {
        assert_eq!(outcome(true, None), "approved");
        for code in [-2, -3, -4, -9] {
            assert_eq!(outcome(false, Some(code)), "cancelled");
        }
        for code in [-1, -8] {
            assert_eq!(outcome(false, Some(code)), "failed");
        }
        assert_eq!(outcome(false, None), "unavailable");
        let input = json!({"id":7,"reason":"CI test","cancel":"Cancel"});
        for value in [
            "approved",
            "cancelled",
            "failed",
            "unsupported",
            "unavailable",
        ] {
            let output = reply(&input, |_, _| {
                Ok(ChildResult {
                    code: Some(0),
                    timed_out: false,
                    stdout: serde_json::to_vec(&json!({"outcome":value,"secret":"FORBIDDEN"}))
                        .unwrap(),
                })
            });
            assert_eq!(output, json!({"id":7,"outcome":value}));
        }
        for (code, timed_out, expected) in [
            (Some(1), false, "unavailable"),
            (None, false, "unavailable"),
            (Some(0), true, "timeout"),
        ] {
            assert_eq!(
                reply(&input, |_, _| Ok(ChildResult {
                    code,
                    timed_out,
                    stdout: br#"{"outcome":"approved"}"#.to_vec(),
                }))["outcome"],
                expected
            );
        }
        for bytes in [
            b"bad".to_vec(),
            br#"{"outcome":"denied"}"#.to_vec(),
            vec![b'x'; 1025],
        ] {
            assert_eq!(
                reply(&input, |_, _| Ok(ChildResult {
                    code: Some(0),
                    timed_out: false,
                    stdout: bytes,
                }))["outcome"],
                "unavailable"
            );
        }
        assert_eq!(
            reply(&input, |_, _| Err(io::ErrorKind::BrokenPipe.into()))["outcome"],
            "unavailable"
        );
    }
}
