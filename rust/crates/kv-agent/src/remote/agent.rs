use super::{queue::DesktopAdmission, Error};
use kv_ipc::agent as wire;
use serde_json::{json, Value};
use std::io::BufRead;
use std::time::Duration;

pub enum Route {
    Reply(Value),
    Dialog,
    Existing,
}

#[derive(Default)]
pub struct AgentSession {
    admission: DesktopAdmission,
}
impl AgentSession {
    pub fn route(&mut self, input: &Value, now: i64) -> Route {
        let id = input["id"].as_u64().unwrap_or(0);
        match self.admission.admit(input, now) {
            Ok(false) => {
                Route::Reply(json!({"id":id,"ok":true,"deferred":input["op"]!="remote_wake"}))
            }
            Err(error) => Route::Reply(json!({"id":id,"ok":false,"error":error.to_string()})),
            Ok(true) => match input["op"].as_str() {
                Some(
                    "remote_approval"
                    | "remote_pair"
                    | "remote_confirm_label"
                    | "remote_confirm_global",
                ) => Route::Dialog,
                _ => Route::Existing,
            },
        }
    }
}

pub fn ui_reply(id: u64, result: super::Result<Value>) -> Value {
    match result {
        Ok(mut reply) if reply.is_object() && reply["ok"] == true => {
            reply["id"] = json!(id);
            reply
        }
        _ => json!({"id":id,"ok":false,"error":Error::UiUnavailable.to_string()}),
    }
}

pub fn read(reader: &mut dyn BufRead) -> std::io::Result<Option<Value>> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(std::io::Error::other("truncated agent frame"))
            };
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let count = newline.map_or(available.len(), |index| index + 1);
        if bytes.len() + count > wire::MAX_LINE_BYTES {
            return Err(std::io::Error::other("agent frame too large"));
        }
        bytes.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline.is_some() {
            return serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(std::io::Error::from);
        }
    }
}

pub trait Connection {
    fn hello(&mut self) -> std::io::Result<Value>;
    fn start_presence(&mut self, device_id: &str);
    fn serve(&mut self) -> std::io::Result<()>;
}

pub trait ConnectionSource {
    /// Authenticate the helper before exposing a channel.
    fn connect(&mut self) -> std::io::Result<Box<dyn Connection>>;
    fn wait(&mut self, duration: Duration) -> bool;
}

pub fn run(source: &mut dyn ConnectionSource, max_backoff: Duration) -> i32 {
    let mut backoff = Duration::from_secs(1);
    loop {
        if let Ok(mut channel) = source.connect() {
            if let Ok(reply) = channel.hello() {
                if reply["reason"] == "not-allowed-user" {
                    return 0;
                }
                if reply["ok"] == true {
                    // CONTRACT: Appendix C / §6.10.1: helper supplies the authenticated device id.
                    if let Some(id) = reply["device_id"].as_str().filter(|id| !id.is_empty()) {
                        channel.start_presence(id);
                    }
                    backoff = Duration::from_secs(1);
                    let _ = channel.serve();
                }
            }
        }
        if !source.wait(backoff) {
            return 0;
        }
        backoff = (backoff * 2).min(max_backoff);
    }
}
