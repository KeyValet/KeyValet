//! Subprocess checks exercise the real parser/help without an installed KeyValet or GUI session.

use serde_json::Value;
use std::process::Command;

#[test]
fn every_remote_help_is_available_without_installation_and_supports_json() {
    for topic in [
        "relay",
        "pair",
        "devices",
        "approvals",
        "approve",
        "deny",
        "grant",
        "remote",
        "status",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_kv-cli"))
            .args([topic, "--help", "--json"])
            .env("KEYVALET_LANG", "en")
            .output()
            .unwrap();
        assert!(output.status.success(), "{topic}: {:?}", output);
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["command"], "help");
        assert!(result["result"]["text"]
            .as_str()
            .unwrap()
            .contains("--json"));
    }
}

#[test]
fn remote_help_matches_the_command_table_and_is_localized() {
    let output = Command::new(env!("CARGO_BIN_EXE_kv-cli"))
        .args(["--lang", "en", "remote", "--help"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    for command in [
        "relay install|status|set-url",
        "pair --new",
        "devices list|revoke",
        "approvals [--watch]",
        "grant ...|list|revoke",
        "mode <per_use|per_credential|per_session|remember:Nh>",
        "allow <--credential",
        "unattended --include-sensitive --until",
        "lock",
        "unlock-ttl",
        "class <name>",
        "label <label>",
        "notify <prefer-local|always-phone|both>",
        "status|pending|grants",
        "audit [--since",
        "status [--summary]",
    ] {
        assert!(text.contains(command), "{command}");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_kv-cli"))
        .args(["--lang", "zh", "pair", "--help"])
        .output()
        .unwrap();
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("用法：keyvalet"));
    let output = Command::new(env!("CARGO_BIN_EXE_kv-cli"))
        .args(["--json", "remote", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["command"],
        "help"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_kv-cli"))
        .args(["--lang", "en", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("Remote approval:"));
}

#[test]
fn invalid_cli_arguments_return_code_two_and_a_stable_error_object() {
    let output = Command::new(env!("CARGO_BIN_EXE_kv-cli"))
        .args(["remote", "srv", "unattended", "--until", "7d", "--json"])
        .env("KEYVALET_LANG", "en")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let body: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["error"]["code"], "invalid_argument");
    assert!(body["error"]["message"].is_string());
    assert_eq!(body.as_object().unwrap().len(), 2);
    assert!(output.stderr.is_empty());
}
