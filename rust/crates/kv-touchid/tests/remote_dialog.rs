#![cfg(target_os = "macos")]
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

#[test]
fn malformed_dialog_cli_input_never_opens_gui_or_contacts_an_installation() {
    for (mode, bytes) in [
        ("--remote-dialog", b"FORBIDDEN".to_vec()),
        (
            "--remote-dialog",
            vec![b'x'; kv_ipc::agent::MAX_LINE_BYTES + 1],
        ),
        ("--remote-dialog", b"{\"op\":\"unknown\"}".to_vec()),
        ("--remote-preview", vec![]),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kv-touchid"))
            .arg(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&bytes).unwrap();
        let result = child.wait_with_output().unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert!(result.stdout.is_empty());
        assert!(matches!(
            std::str::from_utf8(&result.stderr).unwrap().trim(),
            "invalid_remote_request" | "remote_ui_unavailable"
        ));
    }
}

/// Run on this Apple Silicon Mac in an unlocked Aqua session:
/// From rust/: CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w6 cargo test -p kv-touchid -p kv-agent remote_native_screenshots -- --ignored --nocapture
/// Preview children cancel after capture. No installed daemon, software key or Touch ID is used.
#[test]
#[ignore = "Requires an unlocked macOS GUI session; produces native dialog screenshots for human review"]
fn remote_native_screenshots() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let data: Value = serde_json::from_str(
        &std::fs::read_to_string(crate_dir.join("../kv-core/testdata/remote/schema_samples.json"))
            .unwrap(),
    )
    .unwrap();
    let base = data["samples"]
        .as_array()
        .unwrap()
        .iter()
        .find(|sample| sample["type"] == "ApprovalRequest")
        .unwrap()["value"]
        .clone();
    let repository = std::env::var_os("W6_REPOSITORY_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| crate_dir.join("../../.."));
    let assets = repository.join("docs/remote-approval-reports/assets");
    std::fs::create_dir_all(&assets).unwrap();
    let now = kv_touchid::remote::view::unix_seconds();
    for (name, lang, kind, tier, software, standing) in [
        ("w6-approval-zh", "zh", "use", "T1", false, false),
        ("w6-approval-en", "en", "use", "T0", false, false),
        ("w6-sensitive-software", "zh", "use", "T2", true, false),
        ("w6-standing", "zh", "use", "T1", false, true),
        ("w6-unlock", "zh", "unlock", "T1", false, false),
        ("w6-admin", "en", "admin", "T2", false, false),
        ("w6-unattended", "zh", "use", "T2", false, false),
    ] {
        let mut request = base.clone();
        request["exp"] = json!(now + 600);
        request["kind"] = json!(kind);
        request["tier"] = json!(tier);
        if software {
            request["requester"]["protection"]["kind"] = json!("software_key");
        }
        if kind == "unlock" {
            request["credential"] = Value::Null;
            request["operation"] = Value::Null;
        }
        if kind == "admin" {
            request["credential"] = Value::Null;
            request["operation"]["summary"] = json!("admin.add_device");
        }
        if tier == "T2" {
            request["scope_options"] = json!(["per_use"]);
            request["requested_scope"] = json!("per_use");
        }
        if standing {
            request["requested_scope"] = json!("standing:credential");
        }
        request["merged_count"] = json!(3);
        let input = json!({"request":request,"context":{"now":now,"created_at":now-600,"backlog_count":8,"clock_skew_s":90,"unattended":name=="w6-unattended"}});
        let path = assets.join(format!("{name}.png"));
        let mut child = Command::new(env!("CARGO_BIN_EXE_kv-touchid"))
            .args(["--remote-preview", path.to_str().unwrap()])
            .env("KEYVALET_LANG", lang)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&input).unwrap())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "native preview failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(std::fs::metadata(&path).unwrap().len() > 1024);
        println!("{}", path.display());
    }
}

/// Run on this Apple Silicon Mac in an unlocked Aqua session:
/// From rust/: CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w6 cargo test -p kv-touchid -p kv-agent remote_native_pairing_screenshot -- --ignored --nocapture
/// The preview cancels after capture and never calls an approval key or the daemon.
#[test]
#[ignore = "Requires an unlocked macOS GUI session; captures the W0 SAS pairing dialog"]
fn remote_native_pairing_screenshot() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vector: Value = serde_json::from_slice(
        &std::fs::read(crate_dir.join("../kv-core/testdata/remote/pair_sas.json")).unwrap(),
    )
    .unwrap();
    let repository = std::env::var_os("W6_REPOSITORY_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| crate_dir.join("../../.."));
    let assets = repository.join("docs/remote-approval-reports/assets");
    std::fs::create_dir_all(&assets).unwrap();
    let path = assets.join("w6-pair-sas.png");
    let input =
        json!({"op":"remote_pair","peer":vector["initiator"],"sas":vector["expect"]["sas"]});
    let mut child = Command::new(env!("CARGO_BIN_EXE_kv-touchid"))
        .args(["--remote-preview", path.to_str().unwrap()])
        .env("KEYVALET_LANG", "zh")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "native SAS preview failed");
    assert!(std::fs::metadata(&path).unwrap().len() > 1024);
    println!("{}", path.display());
}

#[test]
fn native_reply_selection_cannot_invent_a_scope() {
    let data: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../kv-core/testdata/remote/schema_samples.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let request = data["samples"]
        .as_array()
        .unwrap()
        .iter()
        .find(|sample| sample["type"] == "ApprovalRequest")
        .unwrap()["value"]
        .clone();
    let view = kv_touchid::remote::ApprovalView::new(
        &request,
        kv_touchid::remote::DisplayContext {
            now: 1760200000,
            ..Default::default()
        },
        kv_touchid::remote::Platform::Macos,
    )
    .unwrap();
    assert!(kv_touchid::remote_dialog::NativeDialog::selection(
        &view,
        &json!({"decision":"allow","selected":900})
    )
    .is_err());
    assert!(kv_touchid::remote_dialog::NativeDialog::selection(
        &view,
        &json!({"decision":"allow","selected":-1})
    )
    .is_err());
    assert!(matches!(
        kv_touchid::remote_dialog::NativeDialog::selection(
            &view,
            &json!({"decision":"deny","reason":"Please inspect"})
        )
        .unwrap(),
        kv_touchid::remote::Selection::Deny { .. }
    ));
}
