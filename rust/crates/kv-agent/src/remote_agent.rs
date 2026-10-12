use kv_agent::remote::{self, windows::NativeDialog, Platform};
use kv_ipc::agent as wire;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn read(
    pipe: &mut tokio::net::windows::named_pipe::NamedPipeClient,
) -> std::io::Result<Value> {
    let mut bytes = Vec::new();
    loop {
        let byte = pipe.read_u8().await?;
        if byte == b'\n' {
            break;
        }
        if bytes.len() >= wire::MAX_LINE_BYTES {
            return Err(std::io::Error::other("agent frame too large"));
        }
        bytes.push(byte);
    }
    let mut value: Value = serde_json::from_slice(&bytes)?;
    if let Some(length) = kv_platform::device_key::agent::input_length(&value)
        .map_err(|_| std::io::Error::other("invalid key input length"))?
    {
        let mut input = zeroize::Zeroizing::new(vec![0; length]);
        pipe.read_exact(&mut input).await?;
        value.as_object_mut().unwrap().remove("input_len");
        value["data"] = json!(kv_platform::device_key::encode_b64(&input));
    }
    Ok(value)
}

pub async fn run() {
    let me = match kv_platform::peer::self_identity() {
        Some(identity) => identity,
        None => return,
    };
    if me.elevated || kv_platform::peer::sid_to_string(&me.sid).as_deref() == Some("S-1-5-18") {
        return;
    }
    let mut backoff = std::time::Duration::from_secs(1);
    loop {
        if let Ok(mut channel) =
            kv_platform::pipe::connect_service(kv_platform::paths::AGENT_PIPE).await
        {
            let handshake = async {
                channel
                    .write_all(&wire::encode_line(&wire::hello()))
                    .await?;
                read(&mut channel).await
            };
            if let Ok(Ok(reply)) =
                tokio::time::timeout(std::time::Duration::from_secs(10), handshake).await
            {
                if reply["reason"] == "not-allowed-user" {
                    return;
                }
                if reply["ok"] == true {
                    backoff = std::time::Duration::from_secs(1);
                    let mut presence = reply["device_id"]
                        .as_str()
                        .map(|id| start_presence(id.into(), me.sid.clone()));
                    let mut active = None;
                    let mut session = remote::agent::AgentSession::default();
                    while let Ok(request) = read(&mut channel).await {
                        let id = request["id"].as_u64().unwrap_or(0);
                        if request["op"] == "remote_identity" {
                            let valid = request["device_id"].as_str().filter(|id| {
                                !id.is_empty()
                                    && id.len() <= 256
                                    && !id.chars().any(char::is_control)
                            });
                            if let Some(device_id) = valid {
                                if let Some(task) = presence.take() {
                                    task.abort();
                                }
                                presence = Some(start_presence(device_id.into(), me.sid.clone()));
                            }
                            if channel
                                .write_all(&wire::encode_line(
                                    &json!({"id":id,"ok":valid.is_some()}),
                                ))
                                .await
                                .is_err()
                            {
                                break;
                            }
                            continue;
                        }
                        let enclave = request["op"] == "enclave";
                        let metadata = active.clone();
                        let route = session.route(&request, remote::view::unix_seconds());
                        let result = tokio::task::spawn_blocking(move || match route {
                            remote::agent::Route::Reply(reply) => (reply, None, None),
                            remote::agent::Route::Dialog => {
                                let result = remote::handle_dialog(
                                    &request,
                                    &mut NativeDialog::default(),
                                    Platform::Windows,
                                );
                                (remote::agent::ui_reply(id, result), None, None)
                            }
                            remote::agent::Route::Existing => {
                                super::existing::handle_existing(&request, metadata.as_ref())
                            }
                        })
                        .await;
                        let (reply, payload, updated) = result.unwrap_or_else(|_| {
                            (
                                json!({"id":id,"ok":false,"error":"agent_worker_unavailable"}),
                                None,
                                None,
                            )
                        });
                        if let Some(updated) = updated {
                            active = Some(updated);
                        }
                        if enclave && reply["ok"] != true {
                            active = None;
                        }
                        let data = match payload.as_ref() {
                            Some((data, length))
                                if *length > 0 && *length <= wire::MAX_ENCLAVE_PAYLOAD =>
                            {
                                match data.get(..*length) {
                                    Some(data) => Some(data),
                                    None => break,
                                }
                            }
                            Some(_) => break,
                            None => None,
                        };
                        if channel.write_all(&wire::encode_line(&reply)).await.is_err() {
                            break;
                        }
                        if let Some(data) = data {
                            if channel.write_all(data).await.is_err() {
                                break;
                            }
                        }
                    }
                    if let Some(task) = presence {
                        task.abort();
                    }
                }
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
    }
}

fn start_presence(device_id: String, owner_sid: Vec<u8>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let probe = std::sync::Arc::new(kv_agent::presence::windows::probe(owner_sid));
        let mut reporter = kv_agent::presence::PresenceReporter::new(device_id);
        struct Sink(tokio::runtime::Handle);
        impl kv_agent::presence::PresenceSink for Sink {
            fn send(&mut self, request: &kv_ipc::remote::Request) -> std::io::Result<()> {
                self.0.block_on(async {
                    let mut pipe =
                        kv_platform::pipe::connect_service(kv_platform::paths::HELPER_PIPE).await?;
                    let value = serde_json::to_value(request)?;
                    pipe.write_all(&wire::encode_line(&value)).await?;
                    let reply =
                        tokio::time::timeout(std::time::Duration::from_secs(5), read(&mut pipe))
                            .await
                            .map_err(|_| std::io::Error::other("presence update timed out"))??;
                    if reply["ok"] == true {
                        Ok(())
                    } else {
                        Err(std::io::Error::other("presence update unavailable"))
                    }
                })
            }
        }
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            let probe = probe.clone();
            let mut sink = Sink(tokio::runtime::Handle::current());
            let updated = tokio::task::spawn_blocking(move || {
                let _ = reporter.update(probe.as_ref(), &mut sink, remote::view::unix_seconds());
                reporter
            })
            .await;
            match updated {
                Ok(updated) => reporter = updated,
                Err(_) => return,
            }
        }
    })
}
