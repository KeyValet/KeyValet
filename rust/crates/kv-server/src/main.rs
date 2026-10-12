use std::net::SocketAddr;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match execute().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn execute() -> Result<(), &'static str> {
    let mut listen: SocketAddr = "127.0.0.1:8787".parse().unwrap();
    let mut data = PathBuf::from("/var/lib/keyvalet-relay");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                listen = args
                    .next()
                    .ok_or("missing --listen value")?
                    .parse()
                    .map_err(|_| "invalid listen address")?
            }
            "--data" => data = args.next().ok_or("missing --data value")?.into(),
            "--version" | "-V" => {
                println!("kv-server {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                println!("kv-server [--listen 127.0.0.1:8787] [--data /var/lib/keyvalet-relay]");
                return Ok(());
            }
            _ => return Err("unknown relay option"),
        }
    }
    kv_server::run(listen, data, shutdown_signal())
        .await
        .map_err(|_| "relay failed to bind, open storage or start")
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let terminate = signal(SignalKind::terminate()).map(|mut signal| {
            Box::pin(async move {
                let _ = signal.recv().await;
            }) as Shutdown<()>
        });
        wait_for_shutdown(terminate, Box::pin(tokio::signal::ctrl_c())).await;
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(unix)]
type Shutdown<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

#[cfg(unix)]
async fn wait_for_shutdown(
    terminate: std::io::Result<Shutdown<()>>,
    interrupt: Shutdown<std::io::Result<()>>,
) {
    match terminate {
        Ok(terminate) => tokio::select! { _ = terminate => {}, _ = interrupt => {} },
        Err(_) => {
            let _ = interrupt.await;
        }
    }
}

#[cfg(all(test, unix))]
#[path = "unit_tests/signals.rs"]
mod tests;
