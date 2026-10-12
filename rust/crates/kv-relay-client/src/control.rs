//! Independent control worker, including before the first account/device binding exists.
use crate::{
    client::stopped,
    error::{Error, Result},
    helper::Helper,
};
use kv_core::remote::relay_control::*;
use kv_relay_client::control_transport::RelayApi;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    sync::{watch, Mutex},
    task::JoinSet,
};

#[derive(Clone)]
pub struct Worker {
    helper: Helper,
    relays: Arc<Mutex<HashMap<String, RelayApi>>>,
}
impl Worker {
    pub fn new(helper: Helper) -> Self {
        Self {
            helper,
            relays: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    async fn execute(&self, job: RelayControlJob) {
        let relay = {
            let mut relays = self.relays.lock().await;
            if let Some(relay) = relays.get(&job.relay_url) {
                Ok(relay.clone())
            } else if relays.len() >= 16 {
                Err(kv_relay_client::Error("relay_unreachable"))
            } else {
                RelayApi::new(&job.relay_url).inspect(|relay| {
                    relays.insert(job.relay_url.clone(), relay.clone());
                })
            }
        };
        let result = match relay {
            Ok(relay) => {
                kv_relay_client::controls::execute(&relay, &job, |challenge| async {
                    self.helper
                        .control_sign(job.id.clone(), challenge)
                        .await
                        .map_err(|_| kv_relay_client::Error("invalid_identity_challenge"))
                })
                .await
            }
            Err(error) => RelayControlResult::Failure(RelayControlError::from_code(error.0)),
        };
        // The helper owns request lifetime and retry decisions. Completion after owner
        // cancellation is harmless; it cannot resurrect a pairing or a retired identity.
        let _ = self
            .helper
            .control_complete(RelayControlCompleteParams { id: job.id, result })
            .await;
    }
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut tasks = JoinSet::new();
        loop {
            while tasks.try_join_next().is_some() {}
            if tasks.len() == kv_ipc::MAX_IN_FLIGHT_REQUESTS {
                tokio::select! {
                    _ = stopped(&mut shutdown) => return Ok(()),
                    _ = tasks.join_next() => {},
                }
                continue;
            }
            tokio::select! {
                _ = stopped(&mut shutdown) => { tasks.abort_all(); return Ok(()); },
                polled = self.helper.control_poll() => {
                    match polled {
                        Ok(RelayControlPollResult { request: Some(job) }) => {
                            let worker = self.clone();
                            tasks.spawn(async move { worker.execute(job).await });
                        }
                        Ok(_) => tokio::select! {
                            _ = stopped(&mut shutdown) => return Ok(()),
                            _ = tokio::time::sleep(Duration::from_millis(25)) => {},
                        },
                        Err(Error::HelperUntrusted) => return Err(Error::HelperUntrusted),
                        Err(_) => tokio::select! {
                            _ = stopped(&mut shutdown) => return Ok(()),
                            _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                        },
                    }
                },
            }
        }
    }
}
