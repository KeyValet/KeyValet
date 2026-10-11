use kv_ipc::remote::*;
use serde_json::{json, Value};

#[test]
fn appendix_c_wire_names_roles_and_wrappers_match_the_vector() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kv-core/testdata/remote/ipc_contracts.json");
    let vector: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut allowed = serde_json::Map::new();
    for (name, caller) in [
        ("relay_client", Caller::RelayClient),
        ("hook", Caller::Hook),
        ("mcp", Caller::Mcp),
        ("cli_owner", Caller::CliOwner),
        ("approval_agent", Caller::ApprovalAgent),
    ] {
        allowed.insert(
            name.into(),
            json!(allowed_ops(caller)
                .iter()
                .map(|op| op.as_str())
                .collect::<Vec<_>>()),
        );
    }
    let request: Request = serde_json::from_value(vector["request"].clone()).unwrap();
    let response: Response = serde_json::from_value(vector["response"].clone()).unwrap();
    let observed = json!({"ops": OPS.iter().map(|op| op.as_str()).collect::<Vec<_>>(), "allowed": allowed,
        "request_roundtrip": serde_json::to_value(request).unwrap() == vector["request"],
        "response_roundtrip": serde_json::to_value(response).unwrap() == vector["response"],
        "unknown_op_rejected": Op::parse("remote.future").is_none(),
        "false_success_rejected": serde_json::from_value::<Response>(json!({"ok":false,"result":{}})).is_err()});
    assert!(observed == vector["expect"], "IPC contract vector mismatch");
}
