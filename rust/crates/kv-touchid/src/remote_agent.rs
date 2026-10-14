use kv_ipc::agent as wire;
use kv_touchid::remote::{
    agent::{read, ui_reply, AgentSession, Connection, ConnectionSource, Route},
    flows::Helper,
    Error, Result,
};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

pub struct LocalHelper;
impl Helper for LocalHelper {
    fn exchange(&mut self, request: &kv_ipc::remote::Request) -> Result<Value> {
        let stream = UnixStream::connect(kv_platform::paths::HELPER_SOCKET)
            .map_err(|_| Error::HelperUnavailable)?;
        exchange_on(stream, request, 0)
    }
}

fn exchange_on(
    mut stream: UnixStream,
    request: &kv_ipc::remote::Request,
    owner: u32,
) -> Result<Value> {
    if kv_platform::peer::peer_uid(stream.as_raw_fd()).ok() != Some(owner) {
        return Err(Error::HelperUnavailable);
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|_| Error::HelperUnavailable)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Error::HelperUnavailable)?;
    let value = serde_json::to_value(request).map_err(|_| Error::InvalidRequest)?;
    stream
        .write_all(&wire::encode_line(&value))
        .map_err(|_| Error::HelperUnavailable)?;
    read(&mut BufReader::new(stream))
        .map_err(|_| Error::HelperUnavailable)?
        .ok_or(Error::HelperUnavailable)
}

struct PresenceTransport<H>(H);
impl<H: Helper> kv_touchid::presence::PresenceSink for PresenceTransport<H> {
    fn send(&mut self, request: &kv_ipc::remote::Request) -> std::io::Result<()> {
        match self.0.exchange(request) {
            Ok(reply) if reply["ok"] == true => Ok(()),
            _ => Err(std::io::Error::other("presence update unavailable")),
        }
    }
}

struct PresenceTask {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl PresenceTask {
    fn start(device_id: String) -> Self {
        use kv_platform::presence::{
            macos::MacSignalSource, unix_seconds, DebouncedPresence, IDLE_THRESHOLD_SECONDS,
        };
        let source = MacSignalSource::new(
            unsafe { libc::geteuid() },
            Arc::new(|| Some(std::path::Path::new(kv_platform::paths::TOUCHID_BIN).is_file())),
        );
        let probe = DebouncedPresence::new(source, IDLE_THRESHOLD_SECONDS, unix_seconds());
        Self::start_with(device_id, probe, PresenceTransport(LocalHelper))
    }
    fn start_with(
        device_id: String,
        probe: impl kv_ipc::remote::PresenceProbe + Send + 'static,
        mut sink: impl kv_touchid::presence::PresenceSink + Send + 'static,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            let mut reporter = kv_touchid::presence::PresenceReporter::new(device_id);
            while !stopped.load(Ordering::SeqCst) {
                let _ =
                    reporter.update(&probe, &mut sink, kv_touchid::remote::view::unix_seconds());
                std::thread::sleep(Duration::from_secs(1));
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for PresenceTask {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

type Reply = (Value, Option<(wire::EnclavePayload, usize)>);

fn serve(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    mut dialog: impl FnMut(&[u8]) -> std::io::Result<Vec<u8>>,
    mut existing: impl FnMut(&Value) -> Reply,
    mut now: impl FnMut() -> i64,
) -> std::io::Result<()> {
    let mut session = AgentSession::default();
    while let Some(mut input) = read(reader)? {
        if let Some(length) = kv_platform::device_key::agent::input_length(&input)
            .map_err(|_| std::io::Error::other("invalid key input length"))?
        {
            let mut data = zeroize::Zeroizing::new(vec![0; length]);
            reader.read_exact(&mut data)?;
            input.as_object_mut().unwrap().remove("input_len");
            input["data"] = json!(kv_platform::device_key::encode_b64(&data));
        }
        let id = input["id"].as_u64().unwrap_or(0);
        let (reply, payload) = match session.route(&input, now()) {
            Route::Reply(reply) => (reply, None),
            Route::Dialog => {
                let bytes = serde_json::to_vec(&input)?;
                let result = dialog(&bytes)
                    .map_err(|_| Error::UiUnavailable)
                    .and_then(|bytes| {
                        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)
                    });
                (ui_reply(id, result), None)
            }
            Route::Existing => existing(&input),
        };
        let data = payload
            .as_ref()
            .map(|(data, length)| {
                data.get(..*length)
                    .filter(|_| *length > 0 && *length <= wire::MAX_ENCLAVE_PAYLOAD)
                    .ok_or_else(|| std::io::Error::other("invalid agent payload length"))
            })
            .transpose()?;
        writer.write_all(&wire::encode_line(&reply))?;
        if let Some(data) = data {
            writer.write_all(data)?;
        }
        writer.flush()?;
    }
    Ok(())
}

struct MacConnection {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    presence: Option<PresenceTask>,
}
impl Connection for MacConnection {
    fn hello(&mut self) -> std::io::Result<Value> {
        self.writer
            .set_read_timeout(Some(Duration::from_secs(10)))?;
        self.writer
            .set_write_timeout(Some(Duration::from_secs(5)))?;
        self.writer.write_all(&wire::encode_line(&wire::hello()))?;
        let reply = read(&mut self.reader)?
            .ok_or_else(|| std::io::Error::other("missing agent registration"))?;
        self.writer.set_read_timeout(None)?;
        Ok(reply)
    }
    fn start_presence(&mut self, device_id: &str) {
        self.presence = Some(PresenceTask::start(device_id.into()));
    }
    fn serve(&mut self) -> std::io::Result<()> {
        let presence = &mut self.presence;
        serve(
            &mut self.reader,
            &mut self.writer,
            super::existing::remote_child,
            |input| {
                if input["op"] == "authenticate" {
                    return (
                        super::remote_auth::reply(input, super::remote_auth::child),
                        None,
                    );
                }
                if input["op"] == "remote_identity" {
                    if let Some(id) = input["device_id"].as_str().filter(|id| {
                        !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control)
                    }) {
                        *presence = Some(PresenceTask::start(id.into()));
                        return (json!({"id":input["id"],"ok":true}), None);
                    }
                    return (json!({"id":input["id"],"ok":false}), None);
                }
                super::existing::handle_existing(input)
            },
            kv_touchid::remote::view::unix_seconds,
        )
    }
}
struct MacSource;
impl ConnectionSource for MacSource {
    fn connect(&mut self) -> std::io::Result<Box<dyn Connection>> {
        let writer = UnixStream::connect(kv_platform::paths::AGENT_SOCKET)?;
        if kv_platform::peer::peer_uid(writer.as_raw_fd()).ok() != Some(0) {
            return Err(std::io::Error::other("untrusted agent peer"));
        }
        let reader = BufReader::new(writer.try_clone()?);
        Ok(Box::new(MacConnection {
            reader,
            writer,
            presence: None,
        }))
    }
    fn wait(&mut self, duration: Duration) -> bool {
        std::thread::sleep(duration);
        true
    }
}
pub fn run() -> i32 {
    run_with_dispatcher(
        || kv_touchid::remote::agent::run(&mut MacSource, Duration::from_secs(5)),
        dispatch_macos_notifications,
    )
}

fn run_with_dispatcher(
    work: impl FnOnce() -> i32 + Send + 'static,
    mut dispatch: impl FnMut(Duration),
) -> i32 {
    let (finished, completion) = std::sync::mpsc::channel();
    let Ok(worker) = std::thread::Builder::new()
        .name("kv-agent-ipc".into())
        .spawn(move || {
            let code = work();
            let _ = finished.send(code);
        })
    else {
        return 1;
    };
    loop {
        match completion.recv_timeout(Duration::from_millis(10)) {
            Ok(code) => return worker.join().map_or(1, |_| code),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                dispatch(Duration::from_millis(10));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let _ = worker.join();
                return 1;
            }
        }
    }
}

fn dispatch_macos_notifications(duration: Duration) {
    // Distributed notifications use the main thread's common-mode run loop even
    // when their observer was registered from another thread. Socket reads and
    // authentication subprocesses must not keep this thread from dispatching them.
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFRunLoopDefaultMode: *const std::ffi::c_void;
        fn CFRunLoopRunInMode(
            mode: *const std::ffi::c_void,
            seconds: f64,
            return_after_source: u8,
        ) -> i32;
    }
    unsafe {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, duration.as_secs_f64(), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn r3a_main_thread_notifications_progress_while_private_transport_waits() {
        let main_thread = std::thread::current().id();
        let (notification_tx, notification_rx) = std::sync::mpsc::channel();
        let (delivered_tx, delivered_rx) = std::sync::mpsc::channel();
        let dispatched = Arc::new(AtomicBool::new(false));
        let observed = dispatched.clone();
        let code = run_with_dispatcher(
            move || {
                notification_tx.send("locked").unwrap();
                // A fake socket worker cannot finish until the notification queue is serviced.
                if delivered_rx
                    .recv_timeout(Duration::from_millis(200))
                    .is_ok()
                {
                    0
                } else {
                    3
                }
            },
            move |_| {
                assert_eq!(std::thread::current().id(), main_thread);
                if let Ok(event) = notification_rx.try_recv() {
                    assert_eq!(event, "locked");
                    observed.store(true, Ordering::SeqCst);
                    delivered_tx.send(()).unwrap();
                }
            },
        );
        assert_eq!(
            code, 0,
            "the transport blocked the main-thread notification queue"
        );
        assert!(dispatched.load(Ordering::SeqCst));
    }

    #[test]
    fn r3a_agent_worker_exit_keeps_the_owner_and_failure_status() {
        for status in [0, 1, 6] {
            assert_eq!(run_with_dispatcher(move || status, |_| {}), status);
        }
    }

    #[test]
    fn r3a_agent_worker_panic_cannot_be_a_successful_owner_exit() {
        assert_eq!(
            run_with_dispatcher(|| panic!("fake worker failure"), |_| {}),
            1
        );
    }
    fn fixed(bytes: &[u8]) -> wire::EnclavePayload {
        let mut output = wire::EnclavePayload::new([0; wire::MAX_ENCLAVE_PAYLOAD + 1]);
        output[..bytes.len()].copy_from_slice(bytes);
        output
    }
    #[test]
    fn framed_reader_bounds_and_rejects_truncation() {
        assert_eq!(
            read(&mut &b"{\"ok\":true}\n"[..]).unwrap(),
            Some(json!({"ok":true}))
        );
        assert!(read(&mut &b"{}"[..]).is_err());
        assert!(read(&mut &b"bad\n"[..]).is_err());
        assert_eq!(read(&mut &b""[..]).unwrap(), None);
        assert!(read(&mut &vec![b'x'; wire::MAX_LINE_BYTES + 1][..]).is_err());
    }

    #[test]
    fn session_stream_routes_ui_and_legacy_binary_payloads_without_installation() {
        let mut input = Vec::new();
        for value in [
            json!({"id":1,"op":"remote_wake"}),
            json!({"id":2,"op":"remote_pair"}),
            json!({"id":3,"op":"legacy"}),
            json!({"id":4,"op":"remote_approval","request":null}),
        ] {
            input.extend(wire::encode_line(&value));
        }
        let mut output = Vec::new();
        let mut calls = 0;
        serve(
            &mut input.as_slice(),
            &mut output,
            |input| {
                let request: Value = serde_json::from_slice(input).unwrap();
                assert_eq!(request["id"], 2);
                calls += 1;
                Ok(b"{\"id\":900,\"ok\":true,\"confirmed\":false}".to_vec())
            },
            |input| {
                assert_eq!(input["id"], 3);
                (
                    json!({"id":3,"ok":true,"key_len":2}),
                    Some((fixed(&[7, 8, 9]), 2)),
                )
            },
            || 100,
        )
        .unwrap();
        assert_eq!(calls, 1);
        let mut reader = output.as_slice();
        assert_eq!(read(&mut reader).unwrap().unwrap()["deferred"], false);
        assert_eq!(
            read(&mut reader).unwrap().unwrap(),
            json!({"id":2,"ok":true,"confirmed":false})
        );
        assert_eq!(read(&mut reader).unwrap().unwrap()["key_len"], 2);
        let mut bytes = [0; 2];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [7, 8]);
        assert_eq!(
            read(&mut reader).unwrap().unwrap()["error"],
            "invalid_remote_request"
        );
        assert!(reader.is_empty());
    }

    #[test]
    fn malformed_or_failed_child_output_cannot_panic_or_expose_its_content() {
        let input = wire::encode_line(&json!({"id":u64::MAX,"op":"remote_pair"}));
        for reply in [
            b"null".as_slice(),
            b"[]".as_slice(),
            b"true".as_slice(),
            b"\"FORBIDDEN\"".as_slice(),
            b"bad".as_slice(),
        ] {
            let mut output = Vec::new();
            serve(
                &mut input.as_slice(),
                &mut output,
                |_| Ok(reply.to_vec()),
                |_| panic!("unexpected legacy handler"),
                || 100,
            )
            .unwrap();
            assert_eq!(
                read(&mut output.as_slice()).unwrap().unwrap(),
                json!({"id":u64::MAX,"ok":false,"error":"remote_ui_unavailable"})
            );
        }
        let mut output = Vec::new();
        serve(
            &mut input.as_slice(),
            &mut output,
            |_| Err(std::io::Error::other("FORBIDDEN")),
            |_| panic!("unexpected legacy handler"),
            || 100,
        )
        .unwrap();
        assert!(!String::from_utf8(output).unwrap().contains("FORBIDDEN"));
    }

    #[test]
    fn raw_key_input_is_exact_and_invalid_lengths_or_output_fail_closed() {
        let mut input = wire::encode_line(&json!({"id":1,"op":"device_key","input_len":3}));
        input.extend([0, 10, 255]);
        let mut output = Vec::new();
        serve(
            &mut input.as_slice(),
            &mut output,
            |_| panic!("unexpected UI"),
            |input| {
                assert!(input.get("input_len").is_none());
                assert_eq!(
                    kv_platform::device_key::decode_b64(input["data"].as_str().unwrap())
                        .unwrap()
                        .as_slice(),
                    &[0, 10, 255]
                );
                (json!({"ok":false}), None)
            },
            || 100,
        )
        .unwrap();
        let mut short = input[..input.len() - 1].as_ref();
        assert!(serve(
            &mut short,
            &mut Vec::new(),
            |_| panic!(),
            |_| panic!(),
            || 100
        )
        .is_err());
        let invalid = wire::encode_line(&json!({"op":"device_key","input_len":0}));
        assert!(serve(
            &mut invalid.as_slice(),
            &mut Vec::new(),
            |_| panic!(),
            |_| panic!(),
            || 100
        )
        .is_err());
        let header = wire::encode_line(&json!({"op":"legacy"}));
        let mut output = Vec::new();
        assert!(serve(
            &mut header.as_slice(),
            &mut output,
            |_| panic!(),
            |_| (
                json!({"ok":true}),
                Some((fixed(&[1]), wire::MAX_ENCLAVE_PAYLOAD + 2))
            ),
            || 100
        )
        .is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn agent_stream_preserves_write_payload_and_flush_failures() {
        struct Writer {
            writes: usize,
            fail_write: usize,
            fail_flush: bool,
        }
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.writes += 1;
                if self.writes == self.fail_write {
                    Err(std::io::ErrorKind::BrokenPipe.into())
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                if self.fail_flush {
                    Err(std::io::ErrorKind::BrokenPipe.into())
                } else {
                    Ok(())
                }
            }
        }
        let input = wire::encode_line(&json!({"op":"legacy"}));
        for (fail_write, fail_flush) in [(1, false), (2, false), (0, true)] {
            let mut writer = Writer {
                writes: 0,
                fail_write,
                fail_flush,
            };
            assert_eq!(
                serve(
                    &mut input.as_slice(),
                    &mut writer,
                    |_| panic!(),
                    |_| (json!({"ok":true}), Some((fixed(&[1]), 1))),
                    || 100
                )
                .unwrap_err()
                .kind(),
                std::io::ErrorKind::BrokenPipe
            );
        }
    }

    #[test]
    fn registration_uses_ephemeral_sockets_and_clears_handshake_timeout() {
        for reply in [Some(json!({"ok":true})), None] {
            let accepted = reply.is_some();
            let (writer, mut peer) = UnixStream::pair().unwrap();
            let mut connection = MacConnection {
                reader: BufReader::new(writer.try_clone().unwrap()),
                writer,
                presence: None,
            };
            let (close, closing) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                assert_eq!(
                    read(&mut BufReader::new(peer.try_clone().unwrap())).unwrap(),
                    Some(wire::hello())
                );
                if let Some(reply) = reply {
                    peer.write_all(&wire::encode_line(&reply)).unwrap();
                    closing.recv().unwrap();
                }
            });
            let result = connection.hello();
            if accepted {
                assert_eq!(result.unwrap(), json!({"ok":true}));
                assert_eq!(connection.writer.read_timeout().unwrap(), None);
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "missing agent registration"
                );
            }
            let _ = close.send(());
            thread.join().unwrap();
            if accepted {
                connection.serve().unwrap();
            }
        }
    }

    #[test]
    fn helper_exchange_authenticates_ephemeral_peers_and_bounds_the_response() {
        let request = kv_ipc::remote::Request {
            op: kv_ipc::remote::Op::PresenceUpdate,
            params: json!({"device_id":"dev_mac","state":"away","since":42}),
            extra: Default::default(),
        };
        let owner = unsafe { libc::geteuid() };
        for response in [
            b"{\"ok\":true,\"result\":{}}\n".as_slice(),
            b"bad\n".as_slice(),
            b"".as_slice(),
        ] {
            let (stream, mut peer) = UnixStream::pair().unwrap();
            let expected = serde_json::to_value(&request).unwrap();
            let thread = std::thread::spawn(move || {
                assert_eq!(
                    read(&mut BufReader::new(peer.try_clone().unwrap())).unwrap(),
                    Some(expected)
                );
                peer.write_all(response).unwrap();
            });
            let result = exchange_on(stream, &request, owner);
            if response.starts_with(b"{") {
                assert_eq!(result.unwrap(), json!({"ok":true,"result":{}}));
            } else {
                assert_eq!(result, Err(Error::HelperUnavailable));
            }
            thread.join().unwrap();
        }
        let (stream, mut peer) = UnixStream::pair().unwrap();
        assert_eq!(
            exchange_on(stream, &request, owner ^ 1),
            Err(Error::HelperUnavailable)
        );
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        let (stream, peer) = UnixStream::pair().unwrap();
        drop(peer);
        assert_eq!(
            exchange_on(stream, &request, owner),
            Err(Error::HelperUnavailable)
        );
    }

    #[test]
    fn presence_transport_requires_ack_and_task_stops_with_an_injected_probe() {
        use kv_ipc::remote::{Presence, PresenceProbe, PresenceState};
        use kv_touchid::presence::PresenceSink;
        struct HelperReply(Result<Value>);
        impl Helper for HelperReply {
            fn exchange(&mut self, _: &kv_ipc::remote::Request) -> Result<Value> {
                self.0.clone()
            }
        }
        let request = kv_ipc::remote::Request {
            op: kv_ipc::remote::Op::PresenceUpdate,
            params: json!({}),
            extra: Default::default(),
        };
        for (reply, expected) in [
            (Ok(json!({"ok":true})), true),
            (Ok(json!({"ok":false})), false),
            (Err(Error::HelperUnavailable), false),
        ] {
            assert_eq!(
                PresenceTransport(HelperReply(reply)).send(&request).is_ok(),
                expected
            );
        }
        struct Probe;
        impl PresenceProbe for Probe {
            fn state(&self) -> PresenceState {
                PresenceState {
                    state: Presence::Away,
                    since: 42,
                    signals: serde_json::from_value(json!({})).unwrap(),
                    extra: Default::default(),
                }
            }
        }
        struct Sink(std::sync::mpsc::Sender<kv_ipc::remote::Request>);
        impl PresenceSink for Sink {
            fn send(&mut self, request: &kv_ipc::remote::Request) -> std::io::Result<()> {
                self.0
                    .send(request.clone())
                    .map_err(|_| std::io::Error::other("test receiver unavailable"))
            }
        }
        let (sender, receiver) = std::sync::mpsc::channel();
        let task = PresenceTask::start_with("dev_mac".into(), Probe, Sink(sender));
        let sent = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(sent.params["device_id"], "dev_mac");
        assert_eq!(sent.params["state"], "away");
        assert!(sent.params.get("signals").is_none());
        let stop = task.stop.clone();
        drop(task);
        assert!(stop.load(Ordering::SeqCst));
    }
}
