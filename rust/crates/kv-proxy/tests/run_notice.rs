#![cfg(unix)]

#[tokio::test]
async fn run_notice_fixture() {
    if std::env::var_os("W5_RUN_NOTICE_FIXTURE").is_none() {
        return;
    }
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    sender.send("Fixture MacBook".into()).unwrap();
    drop(sender);
    let mut child = tokio::process::Command::new("/bin/sh");
    child.args(["-c", "sleep 0.1; printf 'synthetic child stderr\n' >&2"]);
    assert!(
        kv_proxy::run::run_with_approval_notices(&mut child, receiver)
            .await
            .unwrap()
            .success()
    );
}

#[test]
fn run_wrapper_and_child_share_stderr_and_include_one_waiting_line() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["run_notice_fixture", "--exact", "--nocapture"])
        .env("W5_RUN_NOTICE_FIXTURE", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("synthetic child stderr"));
    assert!(stderr.contains("Fixture MacBook"));
    assert_eq!(stderr.matches("KeyValet:").count(), 1);
}
