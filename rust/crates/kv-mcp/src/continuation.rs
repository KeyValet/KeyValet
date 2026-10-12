//! Restore only the original tool's formatter after an MCP process restarts.

use crate::gateway_env::{write_gateway_env, write_secret_file};
use crate::tools::common::{fail, ok_data};
use kv_ipc::continuation::{FrontendContinuation, FrontendTool};
use rmcp::model::CallToolResult;
use serde_json::{json, Value};

struct SecretResult(Value);

trait Mail {
    fn export(
        &self,
        session: &str,
        ty: &str,
        name: &str,
        field: Option<&str>,
        secret: &str,
    ) -> Result<std::path::PathBuf, String>;
    fn gateway(
        &self,
        session: &str,
        ty: &str,
        name: &str,
        env: &[(String, String)],
    ) -> Result<std::path::PathBuf, String>;
    fn imap(
        &self,
        opts: crate::mail::ImapTestOpts<'_>,
    ) -> impl std::future::Future<Output = Result<Value, String>> + Send;
    fn graph(
        &self,
        opts: crate::mail::GraphMailOpts<'_>,
    ) -> impl std::future::Future<Output = Result<Value, String>> + Send;
}
struct NativeMail;
impl Mail for NativeMail {
    fn export(
        &self,
        session: &str,
        ty: &str,
        name: &str,
        field: Option<&str>,
        secret: &str,
    ) -> Result<std::path::PathBuf, String> {
        write_secret_file(session, ty, name, field, secret).map_err(|error| error.to_string())
    }
    fn gateway(
        &self,
        session: &str,
        ty: &str,
        name: &str,
        env: &[(String, String)],
    ) -> Result<std::path::PathBuf, String> {
        write_gateway_env(session, ty, name, env).map_err(|error| error.to_string())
    }
    async fn imap(&self, opts: crate::mail::ImapTestOpts<'_>) -> Result<Value, String> {
        crate::mail::imap_xoauth2_test(opts)
            .await
            .and_then(|result| {
                serde_json::to_value(result).map_err(|_| "Invalid IMAP result".into())
            })
    }
    async fn graph(&self, opts: crate::mail::GraphMailOpts<'_>) -> Result<Value, String> {
        crate::mail::graph_mail_test(opts).await.and_then(|result| {
            serde_json::to_value(result).map_err(|_| "Invalid Graph result".into())
        })
    }
}

impl Drop for SecretResult {
    fn drop(&mut self) {
        crate::approval::scrub_value(&mut self.0);
    }
}

pub(crate) async fn restore(
    session: &str,
    frontend: Value,
    result: Value,
) -> Option<CallToolResult> {
    restore_with(session, frontend, result, &NativeMail).await
}

async fn restore_with(
    session: &str,
    frontend: Value,
    result: Value,
    mail: &(impl Mail + Sync),
) -> Option<CallToolResult> {
    let result = SecretResult(result);
    let context: FrontendContinuation = serde_json::from_value(frontend).ok()?;
    if !context.validate() {
        return None;
    }
    let value = &result.0;
    let option = |key: &str| context.options.get(key).and_then(Value::as_str);
    let restored = match context.kind()? {
        FrontendTool::HttpRequest => ok_data(kv_i18n::t("响应：", "Response:"), value),
        FrontendTool::Get => ok_data(
            kv_i18n::t("凭证：", "Credential:"),
            json!({"value": value.get("value"), "fields": value.get("fields")}),
        ),
        FrontendTool::Totp => {
            value["code"].as_str()?;
            ok_data(kv_i18n::t("验证码：", "Code:"), value)
        }
        FrontendTool::Aws => {
            for key in ["access_key_id", "secret_access_key", "session_token"] {
                value[key].as_str()?;
            }
            ok_data(
                kv_i18n::t("AWS 临时凭证：", "AWS temporary credentials:"),
                value,
            )
        }
        FrontendTool::AccessToken => {
            let token = value["access_token"].as_str()?;
            if option("format") == Some("xoauth2") {
                let Some(username) = option("username").or_else(|| value["account"].as_str())
                else {
                    return Some(fail(kv_i18n::t(
                        "无法确定邮箱地址：请传 username，或在授权 scope 中包含 openid email。",
                        "Cannot determine the email address: pass username, or include openid email in the authorization scopes.",
                    )));
                };
                let mut data = value.as_object()?.clone();
                data.insert("username".into(), json!(username));
                data.insert(
                    "xoauth2".into(),
                    json!(crate::mail::xoauth2(username, token)),
                );
                ok_data(
                    kv_i18n::t(
                        "access token（含 XOAUTH2）：",
                        "access token (with XOAUTH2):",
                    ),
                    data,
                )
            } else {
                ok_data(kv_i18n::t("access token：", "access token:"), value)
            }
        }
        FrontendTool::ExportFile => {
            let ty = value["type"].as_str()?;
            let name = value["name"].as_str()?;
            let field = option("field");
            let secret = field
                .and_then(|field| value["fields"][field].as_str())
                .or_else(|| field.is_none().then(|| value["value"].as_str()).flatten())
                .filter(|secret| !secret.is_empty());
            let Some(secret) = secret else {
                return Some(fail(kv_i18n::t(
                    "没有可导出的凭证字段。",
                    "No credential field is available for export.",
                )));
            };
            let path = match mail.export(session, ty, name, field, secret) {
                Ok(path) => path,
                Err(error) => return Some(fail(error.to_string())),
            };
            ok_data(
                kv_i18n::t(
                    "已写入私有文件（内容未返回给我）：",
                    "Written to a private file (content not returned to me):",
                ),
                json!({"path": path.display().to_string(), "note": kv_i18n::t(
                    "不要读取或打印文件内容；直接把路径传给需要文件的命令。",
                    "Do not read or print the file's contents; pass its path directly to the command that needs a file.",
                )}),
            )
        }
        FrontendTool::Test => {
            let status = value["status"].as_i64()?;
            if value["ok"].as_bool()? {
                ok_data(
                    kv_i18n::t(
                        &format!("凭证有效（HTTP {status}）。"),
                        &format!("Credential is valid (HTTP {status})."),
                    ),
                    value,
                )
            } else {
                fail(kv_i18n::t(
                    &format!("凭证验证未通过（HTTP {status}）。\n{value}"),
                    &format!("Credential verification failed (HTTP {status}).\n{value}"),
                ))
            }
        }
        FrontendTool::Gateway => {
            let ty = value["type"].as_str()?;
            let name = value["name"].as_str()?;
            let token = value["token"].as_str()?;
            let base = value["base"].as_str()?;
            let urls = value["base_urls"].as_object()?;
            let mut env = vec![
                ("KEYVALET_GATEWAY_URL".into(), base.into()),
                ("KEYVALET_GATEWAY_TOKEN".into(), token.into()),
            ];
            env.extend(crate::tools::http::sdk_env(
                value["template"].as_str(),
                urls,
                token,
            ));
            let path = match mail.gateway(session, ty, name, &env) {
                Ok(path) => path,
                Err(error) => return Some(fail(error.to_string())),
            };
            ok_data(
                kv_i18n::t("网关已开通：", "Gateway opened:"),
                json!({
                    "env_file": path.display().to_string(), "variables": env.iter().map(|(key, _)| key).collect::<Vec<_>>(),
                    "base_urls": urls,
                }),
            )
        }
        FrontendTool::Imap => {
            let host = option("host")?;
            if host.is_empty()
                || !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
            {
                return None;
            }
            let token = value["access_token"].as_str()?;
            let username = option("username").or_else(|| value["account"].as_str())?;
            let reply = mail
                .imap(crate::mail::ImapTestOpts {
                    host,
                    port: context
                        .options
                        .get("port")
                        .and_then(Value::as_u64)
                        .map(|port| port as u16),
                    username,
                    access_token: token,
                    timeout: std::time::Duration::from_secs(20),
                })
                .await;
            match reply {
                Ok(reply) if reply["authenticated"] == true => ok_data(
                    kv_i18n::t("IMAP 登录成功。", "IMAP login succeeded."),
                    reply,
                ),
                Ok(reply) => fail(kv_i18n::t(
                    &format!("IMAP 登录失败。\n{}", serde_json::to_string(&reply).ok()?),
                    &format!(
                        "IMAP login failed.\n{}",
                        serde_json::to_string(&reply).ok()?
                    ),
                )),
                Err(error) => fail(error),
            }
        }
        FrontendTool::Graph => {
            let token = value["access_token"].as_str()?;
            let folder = option("folder");
            if folder.is_some_and(|f| {
                f.is_empty()
                    || !f
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '=' | '-'))
            }) {
                return None;
            }
            let reply = mail
                .graph(crate::mail::GraphMailOpts {
                    access_token: token,
                    folder,
                    top: context
                        .options
                        .get("top")
                        .and_then(Value::as_u64)
                        .map(|n| n as u32),
                    base_url: None,
                })
                .await;
            match reply {
                Ok(reply) if reply["ok"] == true => ok_data(
                    kv_i18n::t("Graph 读取成功。", "Graph read succeeded."),
                    reply,
                ),
                Ok(reply) => fail(kv_i18n::t(
                    &format!("Graph 读取失败。\n{}", serde_json::to_string(&reply).ok()?),
                    &format!(
                        "Graph read failed.\n{}",
                        serde_json::to_string(&reply).ok()?
                    ),
                )),
                Err(error) => fail(error),
            }
        }
    };
    Some(restored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Effects {
        fail: bool,
        reply: bool,
        observed: Mutex<Vec<String>>,
    }
    impl Mail for Effects {
        fn export(
            &self,
            _: &str,
            _: &str,
            _: &str,
            field: Option<&str>,
            secret: &str,
        ) -> Result<std::path::PathBuf, String> {
            self.observed
                .lock()
                .unwrap()
                .push(format!("{field:?}:{secret}"));
            if self.fail {
                Err("Export failed".into())
            } else {
                Ok("/private/test/key".into())
            }
        }
        fn gateway(
            &self,
            _: &str,
            _: &str,
            _: &str,
            env: &[(String, String)],
        ) -> Result<std::path::PathBuf, String> {
            self.observed
                .lock()
                .unwrap()
                .extend(env.iter().map(|(key, _)| key.clone()));
            if self.fail {
                Err("Gateway file failed".into())
            } else {
                Ok("/private/test/env".into())
            }
        }
        async fn imap(&self, opts: crate::mail::ImapTestOpts<'_>) -> Result<Value, String> {
            self.observed.lock().unwrap().push(format!(
                "{}:{}:{}",
                opts.host,
                opts.port.unwrap_or(993),
                opts.username
            ));
            if self.fail {
                Err("IMAP connection failed".into())
            } else {
                Ok(json!({"authenticated":self.reply}))
            }
        }
        async fn graph(&self, opts: crate::mail::GraphMailOpts<'_>) -> Result<Value, String> {
            self.observed
                .lock()
                .unwrap()
                .push(format!("{:?}:{:?}", opts.folder, opts.top));
            if self.fail {
                Err("Graph connection failed".into())
            } else {
                Ok(json!({"ok":self.reply}))
            }
        }
    }
    fn context(tool: &str, op: &str, options: Value) -> Value {
        json!({"tool":tool,"op":op,"options":options})
    }
    fn serialized(result: CallToolResult) -> String {
        serde_json::to_string(&result).unwrap()
    }

    #[tokio::test]
    async fn every_safe_formatter_restores_without_reissuing_credential_use() {
        let effects = Effects {
            fail: false,
            reply: true,
            observed: Mutex::new(Vec::new()),
        };
        for (tool, op, value) in [
            (
                "credential_http_request",
                "httpRequest",
                json!({"status":200,"body":"original"}),
            ),
            (
                "credential_get",
                "get",
                json!({"value":"original","fields":null}),
            ),
            ("credential_totp_code", "totp", json!({"code":"123456"})),
            (
                "credential_aws_credentials",
                "aws",
                json!({"access_key_id":"a","secret_access_key":"b","session_token":"c"}),
            ),
            (
                "credential_access_token",
                "accessToken",
                json!({"access_token":"short-token"}),
            ),
            (
                "credential_test",
                "httpTest",
                json!({"status":200,"ok":true}),
            ),
            (
                "credential_test",
                "httpTest",
                json!({"status":401,"ok":false}),
            ),
        ] {
            assert!(
                restore_with("session", context(tool, op, json!({})), value, &effects)
                    .await
                    .is_some()
            );
        }
        let value = json!({"access_token":"short-token","account":"user@example.com"});
        let restored = restore_with(
            "session",
            context(
                "credential_access_token",
                "accessToken",
                json!({"format":"xoauth2"}),
            ),
            value,
            &effects,
        )
        .await
        .unwrap();
        assert!(
            serialized(restored).contains(&crate::mail::xoauth2("user@example.com", "short-token"))
        );
        let restored = restore_with(
            "session",
            context(
                "credential_access_token",
                "accessToken",
                json!({"format":"xoauth2"}),
            ),
            json!({"access_token":"short-token"}),
            &effects,
        )
        .await
        .unwrap();
        assert!(restored.is_error.unwrap());
        for field in [json!({}), json!({"field":"key"})] {
            let restored = restore_with("session", context("credential_export_file","get",field), json!({"type":"ssh","name":"key","value":"never-return-secret","fields":{"key":"never-return-secret"}}), &effects).await.unwrap();
            let text = serialized(restored);
            assert!(text.contains("/private/test/key"));
            assert!(!text.contains("never-return-secret"));
        }
        let gateway = json!({"type":"api_key","name":"a","token":"kv_session","base":"http://127.0.0.1:9000","template":"openai","base_urls":{"api.openai.com":"http://127.0.0.1:9000/api.openai.com"}});
        let text = serialized(
            restore_with(
                "session",
                context("credential_gateway", "gatewayOpen", json!({})),
                gateway,
                &effects,
            )
            .await
            .unwrap(),
        );
        assert!(text.contains("OPENAI_API_KEY"));
        assert!(!text.contains("kv_session"));
        for reply in [true, false] {
            for fail in [true, false] {
                let effects = Effects {
                    fail,
                    reply,
                    observed: Mutex::new(Vec::new()),
                };
                for (tool, options) in [
                    (
                        "credential_imap_test",
                        json!({"host":"imap.example.com","port":993,"username":"user@example.com"}),
                    ),
                    (
                        "credential_graph_mail_test",
                        json!({"folder":"inbox","top":5}),
                    ),
                ] {
                    let result = restore_with(
                        "session",
                        context(tool, "accessToken", options),
                        json!({"access_token":"never-return-token"}),
                        &effects,
                    )
                    .await
                    .unwrap();
                    assert_eq!(result.is_error.unwrap_or(false), fail || !reply);
                    assert!(!serialized(result).contains("never-return-token"));
                }
            }
        }
    }

    #[tokio::test]
    async fn corrupt_context_missing_fields_and_failed_exports_never_expose_intermediate_secrets() {
        let effects = Effects {
            fail: true,
            reply: false,
            observed: Mutex::new(Vec::new()),
        };
        for frontend in [
            json!({}),
            context("unknown", "get", json!({})),
            context("credential_get", "totp", json!({})),
            context("credential_get", "get", json!({"secret":"untrusted"})),
        ] {
            assert!(
                restore_with("session", frontend, json!({"value":"sensitive"}), &effects)
                    .await
                    .is_none()
            );
        }
        for (tool, op, options, value) in [
            ("credential_totp_code", "totp", json!({}), json!({})),
            ("credential_aws_credentials", "aws", json!({}), json!({})),
            (
                "credential_access_token",
                "accessToken",
                json!({}),
                json!({}),
            ),
            ("credential_test", "httpTest", json!({}), json!({})),
            ("credential_gateway", "gatewayOpen", json!({}), json!({})),
            (
                "credential_imap_test",
                "accessToken",
                json!({"host":"bad/host"}),
                json!({"access_token":"sensitive"}),
            ),
            (
                "credential_imap_test",
                "accessToken",
                json!({"host":""}),
                json!({"access_token":"sensitive"}),
            ),
            (
                "credential_imap_test",
                "accessToken",
                json!({"host":"imap.example.com"}),
                json!({"access_token":"sensitive"}),
            ),
            (
                "credential_graph_mail_test",
                "accessToken",
                json!({"folder":"bad/folder"}),
                json!({"access_token":"sensitive"}),
            ),
        ] {
            assert!(
                restore_with("session", context(tool, op, options), value, &effects)
                    .await
                    .is_none()
            );
        }
        for options in [json!({}), json!({"field":"missing"})] {
            let result = restore_with(
                "session",
                context("credential_export_file", "get", options),
                json!({"type":"ssh","name":"a","value":"","fields":{"key":"sensitive"}}),
                &effects,
            )
            .await
            .unwrap();
            assert!(result.is_error.unwrap());
            assert!(!serialized(result).contains("sensitive"));
        }
        let result = restore_with(
            "session",
            context("credential_export_file", "get", json!({})),
            json!({"type":"ssh","name":"a","value":"sensitive"}),
            &effects,
        )
        .await
        .unwrap();
        assert!(result.is_error.unwrap());
        assert!(!serialized(result).contains("sensitive"));
        let result = restore_with("session", context("credential_gateway","gatewayOpen",json!({})), json!({"type":"api_key","name":"a","token":"kv_sensitive","base":"http://127.0.0.1:9000","base_urls":{}}), &effects).await.unwrap();
        assert!(result.is_error.unwrap());
        assert!(!serialized(result).contains("kv_sensitive"));
        assert!(restore("session", json!({}), json!({"value":"sensitive"}))
            .await
            .is_none());
    }
}
