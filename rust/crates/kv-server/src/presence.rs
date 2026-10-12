use crate::error::{ApiError, Result};
use crate::messages::{acknowledge, send_messages};
use crate::state::{
    query_rows, random_token, Outbound, Presence, Principal, State as RelayState, HEARTBEAT,
    IDLE_TIMEOUT,
};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Response;
use kv_core::remote::canonical::from_json;
use kv_core::remote::relay::{WsFrame, WS_SUBPROTOCOL};
use kv_core::remote::Envelope;
use rusqlite::params;
use serde_json::{json, Value};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tokio::time::{self, Instant};

#[derive(Clone)]
pub(crate) struct Shutdown(pub watch::Receiver<bool>);

pub(crate) async fn upgrade(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    shutdown: axum::extract::Extension<Shutdown>,
    upgrade: std::result::Result<
        WebSocketUpgrade,
        axum::extract::ws::rejection::WebSocketUpgradeRejection,
    >,
) -> Result<Response> {
    let offered = headers
        .get("sec-websocket-protocol")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h.split(',').any(|p| p.trim() == WS_SUBPROTOCOL));
    if !offered {
        return Err(ApiError::bad());
    }
    let upgrade = upgrade.map_err(|_| ApiError::bad())?;
    let principal = state.with(|data, now| {
        data.rate(
            format!("ws_ip:{}", crate::state::client_ip(peer, &headers)),
            now,
            1,
            60,
        )?;
        let principal = data.authenticate(&headers, now)?;
        data.rate(format!("ws:{}", principal.device.device_id), now, 1, 10)?;
        Ok(principal)
    })?;
    Ok(upgrade
        .protocols([WS_SUBPROTOCOL])
        .max_message_size(crate::http::MAX_BODY)
        .max_frame_size(crate::http::MAX_BODY)
        .on_upgrade(move |socket| serve(Box::new(socket), state, principal, shutdown.0 .0)))
}

fn reconnect(
    state: &RelayState,
    principal: &Principal,
    connection: &str,
    sender: mpsc::Sender<Outbound>,
) -> Result<Vec<Value>> {
    state.with(|data, now| {
        data.check(principal, now, false)?;
        let blobs = query_rows(&data.db, "SELECT m.envelope FROM messages m LEFT JOIN approvals a ON a.account_id=m.account_id AND a.id=m.id
            WHERE m.to_device=?1 AND m.account_id=?2 AND m.acked_at IS NULL AND m.exp>=?3
            AND (m.type NOT IN ('approval_request','approval_escalate') OR (a.state='waiting' AND a.exp>=?3))
            ORDER BY m.created_at,m.id,m.type",
            params![principal.device.device_id, principal.account, now], |row| row.get::<_, Vec<u8>>(0))?;
        let mut frames = Vec::with_capacity(blobs.len());
        for blob in blobs {
            let envelope: Envelope = from_json(&blob)?;
            frames.push(json!({"t":"envelope","envelope":envelope}));
        }
        let pairs = query_rows(&data.db, "SELECT pairing_id,joiner_pubs FROM pairings WHERE initiator_device=?1 AND state='accepted' AND exp>=?2",
            params![principal.device.device_id, now], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
        for (id, record) in pairs {
            let joiner: kv_core::remote::DeviceRecord = from_json(&record)?;
            frames.push(json!({"t":"pair_accept","pairing_id":id,"joiner":joiner}));
        }
        data.db.execute("UPDATE devices SET last_seen=?1 WHERE id=?2", params![now, principal.device.device_id])?;
        data.disconnect(&principal.device.device_id);
        data.presence.insert(principal.device.device_id.clone(), Presence { connection: connection.into(), sender });
        Ok(frames)
    })
}

type SocketFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

trait RelaySocket: Send {
    fn send(&mut self, message: Message) -> SocketFuture<'_, std::result::Result<(), axum::Error>>;
    fn recv(&mut self) -> SocketFuture<'_, Option<std::result::Result<Message, axum::Error>>>;
}

impl RelaySocket for WebSocket {
    fn send(&mut self, message: Message) -> SocketFuture<'_, std::result::Result<(), axum::Error>> {
        Box::pin(WebSocket::send(self, message))
    }

    fn recv(&mut self) -> SocketFuture<'_, Option<std::result::Result<Message, axum::Error>>> {
        Box::pin(WebSocket::recv(self))
    }
}

async fn write(socket: &mut dyn RelaySocket, frame: &Value) -> bool {
    // Value serialization is infallible; only the transport can fail or time out.
    matches!(
        time::timeout(
            Duration::from_secs(5),
            socket.send(Message::Text(frame.to_string().into()))
        )
        .await,
        Ok(Ok(()))
    )
}

use std::time::Duration;

async fn serve(
    mut socket: Box<dyn RelaySocket>,
    state: Arc<RelayState>,
    principal: Principal,
    mut shutdown: watch::Receiver<bool>,
) {
    let connection = random_token(16);
    let (sender, mut inbox) = mpsc::channel(128);
    let initial = match reconnect(&state, &principal, &connection, sender) {
        Ok(frames) => frames,
        Err(_) => return,
    };
    for frame in initial {
        let sent = tokio::select! {
            biased;
            _ = shutdown.changed() => false,
            sent = write(socket.as_mut(), &frame) => sent,
        };
        if !sent {
            remove(&state, &principal, &connection);
            return;
        }
    }
    let mut heartbeat = time::interval_at(Instant::now() + HEARTBEAT, HEARTBEAT);
    heartbeat.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut last_received = Instant::now();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = time::sleep_until(last_received + IDLE_TIMEOUT) => break,
            _ = heartbeat.tick() => {
                if state.with(|data, now| data.check(&principal, now, false)).is_err() { break; }
                if !matches!(time::timeout(Duration::from_secs(5), socket.send(Message::Ping(Vec::new().into()))).await, Ok(Ok(()))) { break; }
            }
            frame = inbox.recv() => match frame {
                Some(Outbound::Frame(frame)) => if !write(socket.as_mut(), &frame).await { break; },
                Some(Outbound::Close) | None => break,
            },
            message = socket.recv() => {
                last_received = Instant::now();
                match message {
                    Some(Ok(Message::Text(text))) => {
                        let result = incoming(&state, &principal, text.as_bytes());
                        let frame = match result { Ok(frame) => frame, Err(error) => serde_json::to_value(error.body()).unwrap() };
                        if !write(socket.as_mut(), &frame).await { break; }
                    }
                    Some(Ok(Message::Ping(bytes))) => {
                        if !matches!(time::timeout(Duration::from_secs(5), socket.send(Message::Pong(bytes))).await, Ok(Ok(()))) { break; }
                    }
                    Some(Ok(Message::Pong(_))) => {},
                    _ => break,
                }
            }
        }
    }
    let _ = time::timeout(Duration::from_secs(1), socket.send(Message::Close(None))).await;
    remove(&state, &principal, &connection);
}

#[cfg(test)]
#[path = "unit_tests/presence.rs"]
mod tests;

fn incoming(state: &RelayState, principal: &Principal, bytes: &[u8]) -> Result<Value> {
    let frame: WsFrame = from_json(bytes)?;
    state.with(|data, now| {
        data.check(principal, now, false)?;
        data.db.execute(
            "UPDATE devices SET last_seen=?1 WHERE id=?2",
            params![now, principal.device.device_id],
        )?;
        match frame {
            WsFrame::Ping { .. } | WsFrame::Pong { .. } => Ok(json!({"t":"pong"})),
            WsFrame::Ack { id, extra } => {
                let kind = extra
                    .get("type")
                    .map(|value| value.as_str().ok_or_else(ApiError::bad))
                    .transpose()?;
                acknowledge(data, principal, std::slice::from_ref(&id), kind, now)?;
                Ok(json!({"t":"ack","id":id}))
            }
            WsFrame::Envelope { envelope, .. } => {
                send_messages(
                    data,
                    principal,
                    std::slice::from_ref(envelope.as_ref()),
                    now,
                )?;
                Ok(json!({"t":"ack","id":envelope.id}))
            }
            WsFrame::PairAccept { .. } | WsFrame::ApprovalCancel { .. } => Err(ApiError::bad()),
        }
    })
}

fn remove(state: &RelayState, principal: &Principal, connection: &str) {
    let _ = state.with(|data, _| {
        if data
            .presence
            .get(&principal.device.device_id)
            .is_some_and(|entry| entry.connection == connection)
        {
            data.presence.remove(&principal.device.device_id);
        }
        Ok(())
    });
}
