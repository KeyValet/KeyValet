//! The helper poller persists outbound traffic even while authentication or the relay is offline.
//! A bounded WS pump keeps heartbeats independent of slow helper and HTTP operations.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use kv_ipc::remote::{Extra, RelayStatusParams};
use serde::Deserialize;
use tokio::{
    sync::{mpsc, watch},
    time::{Instant, MissedTickBehavior},
};
use tokio_tungstenite::tungstenite::Message;

use crate::{
    backoff::Backoff,
    envelope::Envelope,
    error::{Error, Result},
    helper::Helper,
    queue::Queue,
    transport::{unix_now, Group, Relay, Session, Socket, NETWORK_TIMEOUT},
};

#[derive(Clone, Copy)]
pub struct Timing {
    pub heartbeat: Duration,
    pub status: Duration,
    pub initial_backoff: Duration,
    pub maximum_backoff: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            heartbeat: Duration::from_secs(30),
            status: Duration::from_secs(30),
            initial_backoff: Duration::from_secs(1),
            maximum_backoff: Duration::from_secs(60),
        }
    }
}

impl Timing {
    fn backoff(self) -> Backoff {
        Backoff::new(self.initial_backoff, self.maximum_backoff)
    }
}

pub struct Client {
    helper: Helper,
    relay: Relay,
    queue: Queue,
    timing: Timing,
    state: watch::Sender<RelayStatusParams>,
}

impl Client {
    pub fn new(helper: Helper, relay: Relay, queue: Queue) -> Self {
        let (state, _) = watch::channel(RelayStatusParams {
            connected: false,
            last_error: None,
            since: unix_now(),
            extra: Extra::new(),
        });
        Self {
            helper,
            relay,
            queue,
            timing: Timing::default(),
            state,
        }
    }

    #[cfg(test)]
    pub fn with_timing(mut self, timing: Timing) -> Self {
        self.timing = timing;
        self
    }

    fn state(&self, connected: bool, error: Option<&Error>) {
        let last_error = error.map(ToString::to_string);
        self.state.send_if_modified(|state| {
            if state.connected == connected && state.last_error == last_error {
                return false;
            }
            if state.connected != connected {
                state.since = unix_now();
            }
            state.connected = connected;
            state.last_error = last_error.clone();
            true
        });
    }

    pub async fn run(&self, shutdown: watch::Receiver<bool>) -> Result<()> {
        let result = tokio::try_join!(
            self.poll_outbound(shutdown.clone()),
            self.report_status(shutdown.clone()),
            self.connections(shutdown),
        );
        self.state(false, result.as_ref().err());
        // Best effort on shutdown; committed queue files have no dependency on this exchange.
        let state = self.state.borrow().clone();
        let _ = self.helper.status(state).await;
        result.map(|_| ())
    }

    async fn poll_outbound(&self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut backoff = self.timing.backoff();
        loop {
            let envelopes = tokio::select! {
                _ = stopped(&mut shutdown) => return Ok(()),
                result = self.helper.poll() => result,
            };
            match envelopes {
                Ok(envelopes) => {
                    let empty = envelopes.is_empty();
                    self.queue.append(envelopes.clone()).await?;
                    if !empty {
                        if let Err(error) = self
                            .helper
                            .receipt(&envelopes, kv_ipc::remote::OutboundStage::Spooled)
                            .await
                        {
                            let connected = self.state.borrow().connected;
                            self.state(connected, Some(&error));
                            if sleep_or_stop(backoff.delay(None), &mut shutdown).await {
                                return Ok(());
                            }
                            continue;
                        }
                    }
                    backoff.reset();
                    // Defensive against a helper that completes empty long polls immediately.
                    if empty && sleep_or_stop(Duration::from_millis(25), &mut shutdown).await {
                        return Ok(());
                    }
                }
                Err(error) => {
                    let connected = self.state.borrow().connected;
                    self.state(connected, Some(&error));
                    if sleep_or_stop(backoff.delay(None), &mut shutdown).await {
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn report_status(&self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut changes = self.state.subscribe();
        let mut period = tokio::time::interval(self.timing.status);
        period.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = stopped(&mut shutdown) => return Ok(()),
                _ = period.tick() => {},
                _ = changes.changed() => {},
            }
            let state = changes.borrow_and_update().clone();
            tokio::select! {
                _ = stopped(&mut shutdown) => return Ok(()),
                _ = self.helper.status(state) => {},
            }
        }
    }

    async fn connections(&self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let mut backoff = self.timing.backoff();
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            let mut connected_at = None;
            let session_shutdown = shutdown.clone();
            let attempt = async {
                let session = self.relay.authenticate(&self.helper).await?;
                let socket = self.relay.socket(&session).await?;
                connected_at = Some(Instant::now());
                self.state(true, None);
                self.session(socket, &session, session_shutdown).await
            };
            let result = tokio::select! {
                _ = stopped(&mut shutdown) => return Ok(()),
                result = attempt => result,
            };
            if *shutdown.borrow() {
                return Ok(());
            }
            // Do not reset just because auth/WS succeeds: repeated 429/5xx still back off.
            if connected_at.is_some_and(|started| started.elapsed() >= self.timing.heartbeat) {
                backoff.reset();
            }
            match result {
                Ok(()) => {
                    self.state(false, None);
                    backoff.reset();
                }
                Err(error) => {
                    self.state(false, Some(&error));
                    if sleep_or_stop(backoff.delay(error.retry_after()), &mut shutdown).await {
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn session(
        &self,
        socket: Socket,
        session: &Session,
        shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let (inbound_tx, inbound_rx) = mpsc::channel(kv_ipc::MAX_IN_FLIGHT_REQUESTS);
        let (ready_tx, ready_rx) = watch::channel(false);
        // Bound the timer even if a peer supplies an extreme session expiry.
        let renew_after = Duration::from_secs(
            session
                .exp
                .saturating_sub(unix_now())
                .saturating_sub(60)
                .clamp(0, 86400) as u64,
        );
        tokio::select! {
            result = self.pump(socket, inbound_tx, shutdown.clone()) => result,
            result = self.deliver(session, inbound_rx, ready_tx, shutdown.clone()) => result,
            result = self.send_queue(session, ready_rx, shutdown.clone()) => result,
            _ = tokio::time::sleep(renew_after) => Ok(()),
        }
    }

    async fn pump(
        &self,
        mut socket: Socket,
        inbound: mpsc::Sender<Envelope>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let start = Instant::now();
        let mut heartbeat =
            tokio::time::interval_at(start + self.timing.heartbeat, self.timing.heartbeat);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut last_pong = start;
        loop {
            tokio::select! {
                _ = stopped(&mut shutdown) => {
                    let _ = tokio::time::timeout(NETWORK_TIMEOUT, socket.close(None)).await;
                    return Ok(());
                }
                _ = heartbeat.tick() => {
                    if last_pong.elapsed() >= self.timing.heartbeat * 2 { return Err(Error::Network); }
                    send_ws(&mut socket, Message::Text("{\"t\":\"ping\"}".into())).await?;
                }
                frame = socket.next() => {
                    let frame = frame.ok_or(Error::Network)?.map_err(|_| Error::Network)?;
                    match frame {
                        Message::Text(text) => {
                            #[derive(Deserialize)]
                            struct Frame {
                                t: String,
                                #[serde(default)]
                                envelope: Option<Envelope>,
                            }
                            let frame: Frame = serde_json::from_str(&text).map_err(|_| Error::RelayProtocol)?;
                            match frame.t.as_str() {
                                "pong" => last_pong = Instant::now(),
                                "ack" => {}, // Unsolicited relay acks never dequeue outbound files.
                                // W2 emits unsigned metadata hints. Keep transport live; these
                                // cannot replace signed envelopes or change helper-owned state.
                                "pair_accept" | "approval_cancel" => {},
                                "envelope" => {
                                    let envelope = frame.envelope.ok_or(Error::RelayProtocol)?;
                                    // Congestion reconnects; relay retains every envelope until helper ack.
                                    inbound.try_send(envelope).map_err(|_| Error::Network)?;
                                }
                                _ => return Err(Error::RelayProtocol),
                            }
                        }
                        Message::Ping(data) => send_ws(&mut socket, Message::Pong(data)).await?,
                        Message::Pong(_) => last_pong = Instant::now(),
                        Message::Close(_) => return Err(Error::Network),
                        Message::Binary(_) | Message::Frame(_) => return Err(Error::RelayProtocol),
                    }
                }
            }
        }
    }

    async fn deliver(
        &self,
        session: &Session,
        mut inbound: mpsc::Receiver<Envelope>,
        ready: watch::Sender<bool>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        let waiting = tokio::select! {
            _ = stopped(&mut shutdown) => return Ok(()),
            result = self.relay.waiting(session) => result?,
        };
        for envelope in waiting {
            self.deliver_one(session, envelope).await?;
        }
        ready.send_replace(true);
        loop {
            let envelope = tokio::select! {
                _ = stopped(&mut shutdown) => return Ok(()),
                result = inbound.recv() => result.ok_or(Error::Network)?,
            };
            self.deliver_one(session, envelope).await?;
        }
    }

    async fn deliver_one(&self, session: &Session, envelope: Envelope) -> Result<()> {
        // Even malformed/future/expired envelopes go to the helper unchanged. It owns ack policy.
        #[derive(Deserialize)]
        struct Delivery {
            id: String,
            #[serde(rename = "type")]
            kind: String,
        }
        let delivery = serde_json::from_str::<Delivery>(envelope.0.get());
        self.helper.inbound(envelope).await?;
        // A missing transport id prevents relay ack, but must not prevent helper inspection.
        let delivery = delivery.map_err(|_| Error::RelayProtocol)?;
        self.relay.ack(session, &delivery.id, &delivery.kind).await
    }

    async fn send_queue(
        &self,
        session: &Session,
        mut ready: watch::Receiver<bool>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
        while !*ready.borrow() {
            tokio::select! {
                _ = stopped(&mut shutdown) => return Ok(()),
                changed = ready.changed() => { changed.map_err(|_| Error::Network)?; },
            }
        }
        loop {
            let changed = self.queue.changed.notified();
            if *shutdown.borrow() {
                return Ok(());
            }
            if let Some(batch) = self.queue.front().await? {
                let group = Group::first(&batch.envelopes)?;
                let envelopes = &batch.envelopes[..group.count];
                let retired = self
                    .helper
                    .receipt(envelopes, kv_ipc::remote::OutboundStage::Inspect)
                    .await?;
                if retired != 0 {
                    self.queue.complete_prefix(batch.sequence, retired).await?;
                    continue;
                }
                self.relay.send(session, &group, envelopes).await?;
                self.helper
                    .receipt(envelopes, kv_ipc::remote::OutboundStage::Accepted)
                    .await?;
                self.queue
                    .complete_prefix(batch.sequence, group.count)
                    .await?;
            } else {
                tokio::select! {
                    _ = stopped(&mut shutdown) => return Ok(()),
                    _ = changed => {},
                }
            }
        }
    }
}

async fn send_ws(socket: &mut Socket, message: Message) -> Result<()> {
    tokio::time::timeout(NETWORK_TIMEOUT, socket.send(message))
        .await
        .map_err(|_| Error::Network)?
        .map_err(|_| Error::Network)
}

pub async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn sleep_or_stop(delay: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = stopped(shutdown) => true,
        _ = tokio::time::sleep(delay) => false,
    }
}

#[cfg(test)]
#[path = "tests/client.rs"]
mod coverage_tests;
