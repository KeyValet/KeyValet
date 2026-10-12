use std::process::Command;
#[cfg(unix)]
use std::process::{Child, Stdio};
#[cfg(unix)]
use std::time::Duration;

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kv-server"))
}

#[test]
fn options_report_success_and_failure_without_exposing_values() {
    for args in [["--version"], ["-V"], ["--help"], ["-h"]] {
        let output = command().args(args).output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("kv-server"));
    }
    for args in [
        vec!["--listen"],
        vec!["--data"],
        vec!["--listen", "PRIVATE-INVALID-IP"],
        vec!["--PRIVATE-UNKNOWN-OPTION"],
        vec!["--listen", "0.0.0.0:8787"],
    ] {
        let output = command().args(args).output().unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(!error.contains("PRIVATE"));
        assert!(!error.trim().is_empty());
    }
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("file");
    std::fs::write(&file, b"not a directory").unwrap();
    let output = command().arg("--data").arg(&file).output().unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8(output.stderr)
        .unwrap()
        .contains(&file.display().to_string()));
}

#[cfg(unix)]
struct Process(Child);

#[cfg(unix)]
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn production_binary_serves_health_with_private_storage_and_shuts_down_on_signals() {
    use std::os::unix::fs::PermissionsExt;
    for signal in ["-TERM", "-INT"] {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("data");
        let address = {
            let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            reservation.local_addr().unwrap()
        };
        let mut process = Process(
            command()
                .arg("--listen")
                .arg(address.to_string())
                .arg("--data")
                .arg(&data)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let client = reqwest::Client::new();
        let url = format!("http://{address}/v1/health");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                assert!(
                    process.0.try_wait().unwrap().is_none(),
                    "relay exited during startup"
                );
                if let Ok(response) = client.get(&url).send().await {
                    assert_eq!(response.status(), reqwest::StatusCode::OK);
                    let response: serde_json::Value = response.json().await.unwrap();
                    assert_eq!(
                        response,
                        serde_json::json!({"ok":true,"version":env!("CARGO_PKG_VERSION")})
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            std::fs::metadata(&data).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(data.join("relay.sqlite3"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        // kill is the standard Unix signal utility, with no root or installed KeyValet dependency.
        assert!(Command::new("/bin/kill")
            .arg(signal)
            .arg(process.0.id().to_string())
            .status()
            .unwrap()
            .success());
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = process.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}
