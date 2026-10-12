//! Bounded, leased control requests. The networking process gets no key provider: a DK
//! challenge signature is scoped to one helper-created authentication job and used once.
use super::{bootstrap::DeviceKey, engine::random_nonce, Error, Result};
use kv_core::remote::{
    keys::{decode_b64, encode_b64},
    relay_control::*,
    SignatureAlgorithm,
};
use kv_ipc::remote::{Caller, Op, Response};
use serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::{oneshot, Notify};
use tokio::time::Instant;

const CAPACITY: usize = kv_ipc::MAX_IN_FLIGHT_REQUESTS;
const DEADLINE: Duration = Duration::from_secs(45);
struct Entry {
    job: RelayControlJob,
    sender: oneshot::Sender<RelayControlResult>,
    signer: Option<DeviceKey>,
    signature: Option<(String, String)>,
    leased: bool,
    expires: Instant,
}
#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    queue: VecDeque<String>,
}
#[derive(Default)]
pub struct ControlHub {
    state: Mutex<State>,
    changed: Notify,
}
impl ControlHub {
    pub async fn submit(
        &self,
        relay_url: String,
        device_id: Option<String>,
        command: RelayControlCommand,
        signer: Option<DeviceKey>,
    ) -> Result<RelayControlResult> {
        if let RelayControlCommand::Authenticate(local) = &command {
            let identity = signer.as_ref().ok_or(Error("forbidden"))?;
            if identity.public_jwk()? != local.dk_pub {
                return Err(Error("identity_key_mismatch"));
            }
        } else if signer.is_some() {
            return Err(Error("forbidden"));
        }
        let id = random_nonce()?;
        let (sender, receiver) = oneshot::channel();
        {
            let mut state = self.state.lock().map_err(|_| Error("state_unavailable"))?;
            Self::prune(&mut state);
            if state.entries.len() >= CAPACITY {
                return Err(Error("relay_busy"));
            }
            let job = RelayControlJob {
                id: id.clone(),
                relay_url,
                device_id,
                command,
            };
            if serde_json::to_vec(&job)?.len() > kv_ipc::MAX_LINE_BYTES - 1024 {
                return Err(Error("payload_too_large"));
            }
            state.entries.insert(
                id.clone(),
                Entry {
                    job,
                    sender,
                    signer,
                    signature: None,
                    leased: false,
                    expires: Instant::now() + DEADLINE,
                },
            );
            state.queue.push_back(id.clone());
        }
        self.changed.notify_waiters();
        let result = tokio::time::timeout(DEADLINE, receiver).await;
        self.state
            .lock()
            .map_err(|_| Error("state_unavailable"))?
            .entries
            .remove(&id);
        match result {
            Ok(Ok(RelayControlResult::Failure(error))) => Err(Error(error.code())),
            Ok(Ok(result)) => Ok(result),
            _ => Err(Error("relay_unavailable")),
        }
    }
    fn prune(state: &mut State) {
        state
            .entries
            .retain(|_, entry| !entry.sender.is_closed() && entry.expires > Instant::now());
        state.queue.retain(|id| state.entries.contains_key(id));
    }
    pub async fn poll(&self, params: RelayControlPollParams) -> Result<RelayControlPollResult> {
        let wait = Duration::from_millis(params.max_wait_ms.min(30_000));
        let next = async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                {
                    let mut state = self.state.lock().map_err(|_| Error("state_unavailable"))?;
                    Self::prune(&mut state);
                    while let Some(id) = state.queue.pop_front() {
                        if let Some(entry) = state.entries.get_mut(&id) {
                            entry.leased = true;
                            return Ok(RelayControlPollResult {
                                request: Some(entry.job.clone()),
                            });
                        }
                    }
                }
                changed.await;
            }
        };
        match tokio::time::timeout(wait, next).await {
            Ok(result) => result,
            Err(_) => Ok(RelayControlPollResult { request: None }),
        }
    }
    pub fn complete(&self, params: RelayControlCompleteParams) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error("state_unavailable"))?;
        Self::prune(&mut state);
        let entry = state
            .entries
            .get(&params.id)
            .ok_or(Error("unknown_control_request"))?;
        if !entry.leased || !matches_result(&entry.job.command, &params.result) {
            return Err(Error("invalid_control_result"));
        }
        let entry = state
            .entries
            .remove(&params.id)
            .ok_or(Error("unknown_control_request"))?;
        entry
            .sender
            .send(params.result)
            .map_err(|_| Error("unknown_control_request"))
    }
    pub fn sign(&self, params: RelayControlSignParams) -> Result<Value> {
        let bytes = decode_b64(&params.payload_b64)?;
        if bytes.len() != 32 {
            return Err(Error("invalid_identity_challenge"));
        }
        let mut state = self.state.lock().map_err(|_| Error("state_unavailable"))?;
        Self::prune(&mut state);
        let entry = state
            .entries
            .get_mut(&params.id)
            .ok_or(Error("unknown_control_request"))?;
        if !entry.leased || !matches!(entry.job.command, RelayControlCommand::Authenticate(_)) {
            return Err(Error("forbidden"));
        }
        if let Some((challenge, sig)) = &entry.signature {
            if challenge != &params.payload_b64 {
                return Err(Error("identity_challenge_changed"));
            }
            return Ok(serde_json::json!({"sig_b64":sig}));
        }
        let identity = entry.signer.as_ref().ok_or(Error("forbidden"))?;
        let raw = identity.sign(SignatureAlgorithm::ES256, &bytes)?;
        let RelayControlCommand::Authenticate(local) = &entry.job.command else {
            return Err(Error("forbidden"));
        };
        kv_core::remote::verify_identity_signature(
            local,
            &bytes,
            &raw,
        )?;
        let sig = encode_b64(&raw);
        entry.signature = Some((params.payload_b64, sig.clone()));
        Ok(serde_json::json!({"sig_b64":sig}))
    }
}
fn matches_result(command: &RelayControlCommand, result: &RelayControlResult) -> bool {
    use RelayControlCommand as C;
    use RelayControlResult as R;
    if matches!(result, R::Ok(value) if !value.ok) {
        return false;
    }
    if let (C::Messages(request), R::Accepted(value)) = (command, result) {
        if value.accepted != request.envelopes.len() as u64 {
            return false;
        }
    }
    if let (C::RecoverAccount(request), R::Recovered(value)) = (command, result) {
        return value.ok
            && value.account_id == request.account_id
            && value.device_id == request.device.device_id
            && value.recovery_code == request.new_recovery_code;
    }
    matches!(
        (command, result),
        (_, R::Failure(_))
            | (C::Authenticate(_), R::Authenticated { .. })
            | (C::Register(_), R::Registered(_))
            | (C::PairStart(_), R::PairStarted(_))
            | (C::PairComplete(_), R::PairCompleted(_))
            | (C::Messages(_), R::Accepted(_))
            | (
                C::PairFinish(_) | C::Ack(_) | C::DeleteDevice { .. },
                R::Ok(_)
            )
            | (C::Challenge(_), R::Challenge(_))
            | (C::Pending, R::Pending(_))
    )
}
pub fn hub() -> Arc<ControlHub> {
    static HUB: OnceLock<Arc<ControlHub>> = OnceLock::new();
    HUB.get_or_init(|| Arc::new(ControlHub::default())).clone()
}
pub async fn handle(role: Caller, op: Op, value: Value) -> Response {
    if role != Caller::RelayClient {
        return Response::err("forbidden", "forbidden");
    }
    let result = async {
        match op {
            Op::RelayControlPoll => {
                serde_json::to_value(hub().poll(serde_json::from_value(value)?).await?)
                    .map_err(Into::into)
            }
            Op::RelayControlComplete => {
                hub().complete(serde_json::from_value(value)?)?;
                Ok(serde_json::json!({"ok":true}))
            }
            Op::RelayControlSign => hub().sign(serde_json::from_value(value)?),
            _ => Err(Error("forbidden")),
        }
    }
    .await;
    match result {
        Ok(value) => Response::ok(value),
        Err(error) => Response::err(error.code(), error.code()),
    }
}
pub fn is_control(op: Op) -> bool {
    matches!(
        op,
        Op::RelayControlPoll | Op::RelayControlComplete | Op::RelayControlSign
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn pending_requests_are_bounded_leased_and_pruned_after_owner_disconnect() {
        let hub = Arc::new(ControlHub::default());
        let mut tasks = Vec::new();
        for _ in 0..CAPACITY {
            let hub = hub.clone();
            tasks.push(tokio::spawn(async move {
                hub.submit(
                    "https://relay.example.com/".into(),
                    Some("device".into()),
                    RelayControlCommand::Pending,
                    None,
                )
                .await
            }));
        }
        while hub.state.lock().unwrap().entries.len() != CAPACITY {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            hub.submit(
                "https://relay.example.com/".into(),
                None,
                RelayControlCommand::Pending,
                None
            )
            .await
            .unwrap_err()
            .code(),
            "relay_busy"
        );
        let id = hub.state.lock().unwrap().queue.front().unwrap().clone();
        assert_eq!(
            hub.complete(RelayControlCompleteParams {
                id: id.clone(),
                result: RelayControlResult::Pending(Vec::new())
            })
            .unwrap_err()
            .code(),
            "invalid_control_result"
        );
        let job = hub
            .poll(RelayControlPollParams { max_wait_ms: 0 })
            .await
            .unwrap()
            .request
            .unwrap();
        assert_eq!(job.id, id);
        assert_eq!(
            hub.sign(RelayControlSignParams {
                id: id.clone(),
                payload_b64: encode_b64(&[0; 32])
            })
            .unwrap_err()
            .code(),
            "forbidden"
        );
        assert_eq!(
            hub.complete(RelayControlCompleteParams {
                id: id.clone(),
                result: RelayControlResult::Authenticated {
                    account_id: "account".into()
                }
            })
            .unwrap_err()
            .code(),
            "invalid_control_result"
        );
        hub.complete(RelayControlCompleteParams {
            id,
            result: RelayControlResult::Pending(Vec::new()),
        })
        .unwrap();
        assert!(tasks.remove(0).await.unwrap().is_ok());
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
        assert!(hub
            .poll(RelayControlPollParams { max_wait_ms: 0 })
            .await
            .unwrap()
            .request
            .is_none());
        assert!(hub.state.lock().unwrap().entries.is_empty());
    }
    #[tokio::test]
    async fn expired_and_oversized_requests_cannot_be_completed_or_signed() {
        let hub = Arc::new(ControlHub::default());
        let submit = hub.clone();
        let waiting = tokio::spawn(async move {
            submit
                .submit(
                    "https://relay.example.com/".into(),
                    None,
                    RelayControlCommand::Pending,
                    None,
                )
                .await
        });
        let job = hub
            .poll(RelayControlPollParams { max_wait_ms: 1000 })
            .await
            .unwrap()
            .request
            .unwrap();
        hub.state
            .lock()
            .unwrap()
            .entries
            .get_mut(&job.id)
            .unwrap()
            .expires = Instant::now();
        assert!(hub
            .complete(RelayControlCompleteParams {
                id: job.id,
                result: RelayControlResult::Pending(Vec::new())
            })
            .is_err());
        assert_eq!(
            waiting.await.unwrap().unwrap_err().code(),
            "relay_unavailable"
        );
        assert_eq!(
            hub.submit(
                "x".repeat(kv_ipc::MAX_LINE_BYTES),
                None,
                RelayControlCommand::Pending,
                None
            )
            .await
            .unwrap_err()
            .code(),
            "payload_too_large"
        );
    }
    #[tokio::test]
    async fn authentication_uses_the_helpers_identity_and_fixed_error_codes() {
        let hub = ControlHub::default();
        let identity: DeviceKey =
            Arc::new(kv_core::remote::keys::SoftwareDeviceKey::generate_p256());
        let local = kv_core::remote::DeviceRecord {
            device_id: "device".into(),
            label: "Executor".into(),
            os: kv_core::remote::Os::Linux,
            key_kind: kv_core::remote::KeyKind::Software,
            dk_pub: identity.public_jwk().unwrap(),
            dk_sig: kv_core::remote::Optional::Missing,
            ak_q: None,
            ak_s: None,
            caps: vec![kv_core::remote::Capability::Execute],
            attestation: None,
            extra: Default::default(),
        };
        assert_eq!(
            hub.submit(
                "https://relay.example.com/".into(),
                None,
                RelayControlCommand::Authenticate(local.clone()),
                None
            )
            .await
            .unwrap_err()
            .code(),
            "forbidden"
        );
        let wrong = Arc::new(kv_core::remote::keys::SoftwareDeviceKey::generate_p256());
        assert_eq!(
            hub.submit(
                "https://relay.example.com/".into(),
                None,
                RelayControlCommand::Authenticate(local),
                Some(wrong)
            )
            .await
            .unwrap_err()
            .code(),
            "identity_key_mismatch"
        );
        assert_eq!(
            hub.submit(
                "https://relay.example.com/".into(),
                None,
                RelayControlCommand::Pending,
                Some(identity)
            )
            .await
            .unwrap_err()
            .code(),
            "forbidden"
        );
        for op in [
            Op::RelayControlPoll,
            Op::RelayControlComplete,
            Op::RelayControlSign,
        ] {
            let response = serde_json::to_value(
                handle(
                    Caller::RelayClient,
                    op,
                    serde_json::json!({"message":"PRIVATE-MARKER"}),
                )
                .await,
            )
            .unwrap();
            assert_eq!(response["error"]["code"], "invalid_json");
            assert!(!response.to_string().contains("PRIVATE-MARKER"));
        }
        assert_eq!(
            serde_json::to_value(handle(Caller::RelayClient, Op::Status, Value::Null).await)
                .unwrap()["error"]["code"],
            "forbidden"
        );
    }
}
