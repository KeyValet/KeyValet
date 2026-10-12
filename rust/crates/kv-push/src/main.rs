use kv_push::{load_apns, load_fcm, router, Dispatcher};
use std::{env, path::Path};
fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(env::var(name).map_err(|_| format!("Missing {name}"))?)
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let apns = if let Ok(path) = env::var("KV_APNS_KEY_FILE") {
        Some(
            load_apns(
                Path::new(&path),
                required("KV_APNS_TEAM")?,
                required("KV_APNS_KEY_ID")?,
                required("KV_APNS_TOPIC")?,
                env::var("KV_APNS_SANDBOX").as_deref() == Ok("1"),
            )
            .map_err(|_| "Invalid APNs configuration")?,
        )
    } else {
        None
    };
    let fcm = env::var("KV_FCM_SERVICE_ACCOUNT_FILE")
        .ok()
        .map(|path| load_fcm(Path::new(&path)).map_err(|_| "Invalid FCM configuration"))
        .transpose()?;
    if apns.is_none() && fcm.is_none() {
        return Err("Configure APNs or FCM".into());
    }
    let dispatch = Dispatcher::new(apns, fcm).map_err(|_| "Invalid transport configuration")?;
    let bearer = if let Some(path) = env::var_os("KV_PUSH_RELAY_BEARER_FILE") {
        let text = zeroize::Zeroizing::new(
            std::fs::read_to_string(path).map_err(|_| "Cannot read relay credential file")?,
        );
        text.trim().to_owned()
    } else {
        required("KV_PUSH_RELAY_BEARER")?
    };
    let app = router(dispatch, bearer).map_err(|_| "Invalid relay authentication")?;
    let port = env::var("KV_PUSH_PORT")
        .unwrap_or_else(|_| "8788".into())
        .parse::<u16>()?;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
