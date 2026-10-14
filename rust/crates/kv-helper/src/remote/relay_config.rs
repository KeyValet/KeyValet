//! Authoritative absence probe for the protected Windows relay configuration.
//! It neither reads configuration contents nor exposes a caller-selected path.
use kv_ipc::remote::{Caller, Response};
use serde_json::Value;

pub(super) fn handle(caller: Caller, params: Value) -> Response {
    #[cfg(windows)]
    {
        handle_at(
            caller,
            params,
            std::path::Path::new(kv_platform::paths::RELAY_CONFIG),
        )
    }
    #[cfg(not(windows))]
    {
        // Other platforms already distinguish NotFound without privileged assistance.
        match validate(caller, &params) {
            Err(code) => Response::err(code, code),
            Ok(()) => Response::err("remote_unavailable", "remote_unavailable"),
        }
    }
}

fn validate(caller: Caller, params: &Value) -> Result<(), &'static str> {
    if caller != Caller::RelayClient {
        return Err("forbidden");
    }
    if !params.as_object().is_some_and(serde_json::Map::is_empty) {
        return Err("invalid_params");
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn handle_at(caller: Caller, params: Value, path: &std::path::Path) -> Response {
    if let Err(code) = validate(caller, &params) {
        return Response::err(code, code);
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => Response::ok(serde_json::json!({"exists": true})),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Response::ok(serde_json::json!({"exists": false}))
        }
        Err(_) => Response::err("relay_config_unavailable", "relay_config_unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fixed_config_probe_reports_absence_and_presence_without_reading_contents() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay-client.toml");
        let response =
            |params| serde_json::to_value(handle_at(Caller::RelayClient, params, &path)).unwrap();
        assert_eq!(
            response(json!({})),
            json!({"ok":true,"result":{"exists":false}})
        );
        std::fs::write(
            &path,
            "deliberately invalid; never parse or return this text",
        )
        .unwrap();
        assert_eq!(
            response(json!({})),
            json!({"ok":true,"result":{"exists":true}})
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(response(json!({}))["result"]["exists"], true);
    }

    #[test]
    fn probe_rejects_other_roles_and_any_path_or_identity_parameters() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("absent");
        for caller in [
            Caller::Hook,
            Caller::Mcp,
            Caller::CliOwner,
            Caller::ApprovalAgent,
        ] {
            assert!(!kv_ipc::remote::allowed_ops(caller)
                .contains(&kv_ipc::remote::Op::RelayConfigPresence));
            assert_eq!(
                serde_json::to_value(handle_at(caller, json!({}), &path)).unwrap()["error"]["code"],
                "forbidden"
            );
        }
        for params in [
            json!({"path":"other"}),
            json!({"device_id":"dev"}),
            Value::Null,
            json!([]),
        ] {
            assert_eq!(
                serde_json::to_value(handle_at(Caller::RelayClient, params, &path)).unwrap()
                    ["error"]["code"],
                "invalid_params"
            );
        }
    }
}
