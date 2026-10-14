//! Configuration and command validation, independent of the process and service adapters.

use std::{ffi::OsString, path::Path};

use tokio::sync::watch;

use crate::{
    client::Client,
    config::Config,
    error::{Error, Result},
    helper::Helper,
    queue::Queue,
    transport::Relay,
};

pub enum Action {
    Help,
    Run,
    #[cfg(windows)]
    Service,
    #[cfg(windows)]
    Install,
    #[cfg(windows)]
    Uninstall,
}

pub fn parse(arguments: &[OsString]) -> Result<Action> {
    match arguments {
        [] => Ok(Action::Run),
        [help] if help == "--help" || help == "-h" => Ok(Action::Help),
        #[cfg(windows)]
        [service] if service == "--service" => Ok(Action::Service),
        #[cfg(windows)]
        [service, action] if service == "service" && action == "install" => Ok(Action::Install),
        #[cfg(windows)]
        [service, action] if service == "service" && action == "uninstall" => Ok(Action::Uninstall),
        _ => Err(Error::Config),
    }
}

pub async fn run(
    config_path: &Path,
    queue_path: &Path,
    helper: Helper,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let prepared = Config::load_for_service(config_path, &helper)
        .await?
        .map(|config| -> Result<(Config, Client)> {
            Ok((
                config.clone(),
                Client::new(
                    helper.clone(),
                    Relay::new(&config)?,
                    Queue::open(queue_path)?,
                ),
            ))
        })
        .transpose()?;
    let controls = crate::control::Worker::new(helper.clone());
    tokio::select! {
        result = controls.run(shutdown.clone()) => result,
        result = run_bound(config_path, queue_path, helper, prepared, shutdown) => result,
    }
}

async fn run_bound(
    config_path: &Path,
    queue_path: &Path,
    helper: Helper,
    mut prepared: Option<(Config, Client)>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    #[cfg(windows)]
    let mut reported_binding = None;
    // Pairing itself creates the first binding. Keep the authenticated control worker alive
    // while no configuration exists; never invent a device/account or contact a default relay.
    loop {
        let bound = match prepared.take() {
            Some(bound) => Some(bound),
            None => Config::load_for_service(config_path, &helper)
                .await?
                .map(|config| -> Result<(Config, Client)> {
                    Ok((
                        config.clone(),
                        Client::new(
                            helper.clone(),
                            Relay::new(&config)?,
                            Queue::open(queue_path)?,
                        ),
                    ))
                })
                .transpose()?,
        };
        #[cfg(windows)]
        if reported_binding != Some(bound.is_some()) {
            crate::windows::report_binding(bound.is_some());
            reported_binding = Some(bound.is_some());
        }
        if let Some((config, client)) = bound {
            let (stop, child_shutdown) = watch::channel(false);
            let running = client.run(child_shutdown);
            tokio::pin!(running);
            let mut reload = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tokio::select! {
                    result = &mut running => return result,
                    _ = crate::client::stopped(&mut shutdown) => {
                        let _ = stop.send(true);
                        return running.await;
                    },
                    _ = reload.tick() => {
                        if Config::load_for_service(config_path, &helper).await?.as_ref() != Some(&config) {
                            let _ = stop.send(true);
                            running.await?;
                            break;
                        }
                    },
                }
            }
        }
        if *shutdown.borrow() {
            return Ok(());
        }
        tokio::select! {
            _ = crate::client::stopped(&mut shutdown) => return Ok(()),
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {},
        }
    }
}
