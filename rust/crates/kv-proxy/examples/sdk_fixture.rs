//! Loopback-only SDK verification, with a disposable vault and synthetic helper outcomes.
use futures_util::future::BoxFuture;
use kv_proxy::{
    approval::{ApprovalLayer, ApprovalProvider, ApprovalRequest},
    gateway::Gateway,
};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

struct Helper {
    requests: AtomicUsize,
    log: std::path::PathBuf,
}

struct SyntheticConfirmation;
impl kv_platform::Confirmer for SyntheticConfirmation {
    async fn confirm(&self, _: &str, _: &str) -> bool {
        true
    }
}
impl ApprovalProvider for Helper {
    fn authorize(&self, request: ApprovalRequest) -> BoxFuture<'_, Result<Value, String>> {
        Box::pin(async move {
            use std::io::Write;
            let number = self.requests.fetch_add(1, Ordering::SeqCst) + 1;
            let state = request
                .headers
                .get("x-r2d-state")
                .map_or("ok", String::as_str);
            let _ = writeln!(
                std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(&self.log)
                    .unwrap(),
                "{}",
                json!({"request":number,"method":request.method,"url":request.url,"state":state})
            );
            let id = format!("01J{number:023}");
            if state == "approval_cancelled" {
                return Ok(
                    json!({"status":"approval_expired","reason":"cancelled","approval_id":id}),
                );
            }
            if state != "ok" {
                return Ok(json!({"status":state,"approval_id":id}));
            }
            let body = if request.url.contains("anthropic") {
                json!({"id":"msg_r2d","type":"message","role":"assistant","model":"synthetic","content":[{"type":"text","text":"SDK_GATEWAY_OK"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}})
            } else {
                json!({"id":"chatcmpl-r2d","object":"chat.completion","created":1,"model":"synthetic","choices":[{"index":0,"message":{"role":"assistant","content":"SDK_GATEWAY_OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}})
            };
            Ok(
                json!({"status":"ok","approval_id":id,"result":{"status":200,"headers":{"content-type":"application/json"},"body":body.to_string(),"body_encoding":"text"}}),
            )
        })
    }
    fn wait(&self, _: String, _: Duration) -> BoxFuture<'_, Result<Value, String>> {
        Box::pin(async { Err("An immediate fixture outcome must not wait".into()) })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(kv_vault::Vault::new(dir.path().join("vault")));
    vault.prepare()?;
    std::fs::write(vault.dir.join("master.key"), [7u8; 32])?;
    kv_platform::fs::set_private_permissions(&vault.dir.join("master.key"))?;
    vault.init_legacy()?;
    vault.set(kv_vault::SetParams {
        r#type: "api_key".into(),
        name: "fixture".into(),
        value: Some("synthetic-private-sdk-value".into()),
        ..Default::default()
    })?;
    kv_proxy::manage::configure_http(
        &vault,
        kv_proxy::manage::ConfigureHttpParams {
            r#type: "api_key",
            name: "fixture",
            purpose: "Disposable SDK fixture",
            remove: false,
            allowed_hosts: Some(&json!(["*.openai.com", "*.anthropic.com"])),
            inject: Some(&json!({"headers":{"Authorization":"Bearer {{value}}"}})),
            proxy_only: None,
            test: None,
        },
        &SyntheticConfirmation,
    )
    .await?;
    let args: Vec<String> = std::env::args().collect();
    let log = std::path::PathBuf::from(&args[1]);
    let audit_log = Arc::new(Mutex::new(
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&args[2])?,
    ));
    let gateway = Gateway::new(
        vault,
        Arc::new(move |event| {
            let _ = writeln!(audit_log.lock().unwrap(), "{}", Value::Object(event));
        }),
        None,
    )
    .with_approval(ApprovalLayer {
        provider: Arc::new(Helper {
            requests: AtomicUsize::new(0),
            log,
        }),
        http_wait: Duration::from_secs(1),
        notice: None,
    });
    let entry = gateway
        .open(
            "api_key",
            "fixture",
            Some("R2-D official SDK loopback verification"),
        )
        .await?;
    println!("{}", json!({"base":entry.base,"token":entry.token}));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = std::io::stdin().read_line(&mut String::new());
        let _ = stop.send(());
    });
    let _ = stopped.await;
    gateway.shutdown().await;
    Ok(())
}
