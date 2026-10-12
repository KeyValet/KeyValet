//! Bounded frontend formatting metadata. Operation bodies and secrets never belong here.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Deserialize)]
pub enum FrontendTool {
    #[serde(rename = "credential_get")]
    Get,
    #[serde(rename = "credential_http_request")]
    HttpRequest,
    #[serde(rename = "credential_test")]
    Test,
    #[serde(rename = "credential_totp_code")]
    Totp,
    #[serde(rename = "credential_aws_credentials")]
    Aws,
    #[serde(rename = "credential_access_token")]
    AccessToken,
    #[serde(rename = "credential_export_file")]
    ExportFile,
    #[serde(rename = "credential_gateway")]
    Gateway,
    #[serde(rename = "credential_imap_test")]
    Imap,
    #[serde(rename = "credential_graph_mail_test")]
    Graph,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendContinuation {
    pub tool: String,
    pub op: String,
    #[serde(default)]
    pub options: Map<String, Value>,
}

impl FrontendContinuation {
    pub fn kind(&self) -> Option<FrontendTool> {
        serde_json::from_value(Value::String(self.tool.clone())).ok()
    }
    pub fn capture(tool: &str, op: &str, arguments: &Map<String, Value>) -> Option<Self> {
        let fields = fields(tool, op)?;
        let options = arguments
            .iter()
            .filter(|(name, value)| fields.contains(&name.as_str()) && !value.is_null())
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let value = Self {
            tool: tool.into(),
            op: op.into(),
            options,
        };
        value.validate().then_some(value)
    }

    pub fn validate(&self) -> bool {
        let Some(fields) = fields(&self.tool, &self.op) else {
            return false;
        };
        self.options.iter().all(|(name, value)| {
            fields.contains(&name.as_str())
                && match name.as_str() {
                    "port" => value.as_u64().is_some_and(|n| (1..=65535).contains(&n)),
                    "top" => value.as_u64().is_some_and(|n| (1..=20).contains(&n)),
                    _ => value
                        .as_str()
                        .is_some_and(|s| s.len() <= 300 && !s.chars().any(char::is_control)),
                }
        })
    }
}

fn fields(tool: &str, op: &str) -> Option<&'static [&'static str]> {
    match (tool, op) {
        ("credential_get", "get")
        | ("credential_http_request", "httpRequest")
        | ("credential_test", "httpTest")
        | ("credential_totp_code", "totp")
        | ("credential_aws_credentials", "aws")
        | ("credential_gateway", "gatewayOpen") => Some(&[]),
        ("credential_export_file", "get") => Some(&["field"]),
        ("credential_access_token", "accessToken") => Some(&["format", "username"]),
        ("credential_imap_test", "accessToken") => Some(&["host", "port", "username"]),
        ("credential_graph_mail_test", "accessToken") => Some(&["folder", "top"]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn captures_only_formatter_options_and_binds_the_original_tool_to_its_operation() {
        let input = json!({"field":"private_key", "value":"SECRET", "body":"SECRET", "headers":{"authorization":"SECRET"}});
        let context = FrontendContinuation::capture(
            "credential_export_file",
            "get",
            input.as_object().unwrap(),
        )
        .unwrap();
        assert_eq!(
            context.options,
            json!({"field":"private_key"}).as_object().unwrap().clone()
        );
        assert!(!serde_json::to_string(&context).unwrap().contains("SECRET"));
        assert!(FrontendContinuation::capture(
            "credential_export_file",
            "httpRequest",
            input.as_object().unwrap()
        )
        .is_none());
        for (tool, op) in [
            ("credential_get", "get"),
            ("credential_http_request", "httpRequest"),
            ("credential_test", "httpTest"),
            ("credential_totp_code", "totp"),
            ("credential_aws_credentials", "aws"),
            ("credential_gateway", "gatewayOpen"),
            ("credential_access_token", "accessToken"),
            ("credential_graph_mail_test", "accessToken"),
        ] {
            assert!(FrontendContinuation::capture(tool, op, &Map::new())
                .unwrap()
                .validate());
        }
    }

    #[test]
    fn rejects_unknown_fields_oversized_text_controls_and_invalid_numeric_options() {
        let base = FrontendContinuation {
            tool: "credential_imap_test".into(),
            op: "accessToken".into(),
            options: Map::new(),
        };
        for options in [
            json!({"password":"secret"}),
            json!({"host":"x".repeat(301)}),
            json!({"host":"x\ny"}),
            json!({"host":null}),
            json!({"host":3}),
            json!({"port":0}),
            json!({"port":65536}),
            json!({"port":1.5}),
        ] {
            let mut context = base.clone();
            context.options = options.as_object().unwrap().clone();
            assert!(!context.validate(), "{options}");
        }
        for n in [1, 65535] {
            let mut context = base.clone();
            context.options.insert("port".into(), json!(n));
            assert!(context.validate());
        }
        for n in [0, 1, 20, 21] {
            let context = FrontendContinuation::capture(
                "credential_graph_mail_test",
                "accessToken",
                json!({"top":n}).as_object().unwrap(),
            );
            assert_eq!(context.is_some(), (1..=20).contains(&n));
        }
        assert!(serde_json::from_value::<FrontendContinuation>(
            json!({"tool":"credential_get","op":"get","secret":"hidden"})
        )
        .is_err());
    }
}
