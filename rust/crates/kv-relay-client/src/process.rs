//! Native process runtime, signals and fixed installation locations.

use tokio::sync::watch;

use crate::{
    app::{self, Action},
    error::{Error, Result},
    helper::Helper,
    platform,
};

pub fn entry() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match app::parse(&arguments)? {
        Action::Help => {
            println!("Usage: kv-relay-client [--service | service install | service uninstall]");
            return Ok(());
        }
        Action::Run => {}
        #[cfg(windows)]
        Action::Service => return crate::windows::dispatch(),
        #[cfg(windows)]
        Action::Install => return crate::windows::install(),
        #[cfg(windows)]
        Action::Uninstall => return crate::windows::uninstall(),
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::Config)?;
    let (shutdown, receiver) = watch::channel(false);
    runtime.block_on(async move {
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                if let Ok(mut terminate) = signal(SignalKind::terminate()) {
                    tokio::select! {
                        _ = terminate.recv() => {},
                        _ = tokio::signal::ctrl_c() => {},
                    }
                } else {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
            #[cfg(windows)]
            let _ = tokio::signal::ctrl_c().await;
            let _ = shutdown.send(true);
        });
        run_daemon(receiver).await
    })
}

pub async fn run_daemon(shutdown: watch::Receiver<bool>) -> Result<()> {
    platform::verify_runtime_account()?;
    app::run(
        &platform::config_path()?,
        &platform::queue_path()?,
        Helper::new(),
        shutdown,
    )
    .await
}
