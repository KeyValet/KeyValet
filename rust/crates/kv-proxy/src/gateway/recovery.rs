//! Session-local recovery for a client that disconnects while approval is pending.
//! An HTTP permit is claimed once. Only a detached, completed response is retained.

use super::*;
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::sync::oneshot;
use zeroize::Zeroize;

const MAX_TICKETS: usize = MAX_IN_FLIGHT;
const MAX_RETAINED_BODY: usize = 8 * 1024 * 1024;
pub(super) type Reply = Result<Response<BoxBody>, (StatusCode, String, String)>;

#[derive(PartialEq, Eq)]
struct Binding {
    credential_type: String,
    credential_name: String,
    method: String,
    url: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    purpose: Option<String>,
}

impl From<&crate::approval::ApprovalRequest> for Binding {
    fn from(request: &crate::approval::ApprovalRequest) -> Self {
        Self {
            credential_type: request.credential_type.clone(),
            credential_name: request.credential_name.clone(),
            method: request.method.clone(),
            url: request.url.clone(),
            headers: request.headers.clone(),
            body: request.body.to_vec(),
            purpose: request.purpose.clone(),
        }
    }
}

impl Drop for Binding {
    fn drop(&mut self) {
        self.body.zeroize();
        self.url.zeroize();
        self.headers.values_mut().for_each(Zeroize::zeroize);
        self.purpose.zeroize();
    }
}

struct Retained {
    status: StatusCode,
    headers: hyper::HeaderMap,
    body: zeroize::Zeroizing<Vec<u8>>,
}

impl Retained {
    async fn collect(response: Response<BoxBody>) -> Self {
        let (parts, body) = response.into_parts();
        match Limited::new(body, MAX_RETAINED_BODY).collect().await {
            Ok(body) => Self {
                status: parts.status,
                headers: parts.headers,
                body: zeroize::Zeroizing::new(body.to_bytes().to_vec()),
            },
            Err(_) => {
                let response = crate::approval::error_response(StatusCode::BAD_GATEWAY,
                    "keyvalet_response_unavailable", "The detached response was interrupted or exceeded the 8 MiB recovery limit. The request will not execute again.", None);
                let (parts, body) = response.into_parts();
                Self {
                    status: parts.status,
                    headers: parts.headers,
                    body: zeroize::Zeroizing::new(
                        body.collect().await.unwrap().to_bytes().to_vec(),
                    ),
                }
            }
        }
    }

    fn response(mut self) -> Response<BoxBody> {
        let mut response = Response::new(full_body(std::mem::take(&mut *self.body)));
        *response.status_mut() = self.status;
        *response.headers_mut() = std::mem::take(&mut self.headers);
        response
    }
}

impl Drop for Retained {
    fn drop(&mut self) {
        // Header values can also contain upstream data. Replace before dropping them.
        self.headers.clear();
    }
}

enum State {
    Running,
    Ready(Retained),
    Consumed,
}

pub(super) struct Entry {
    epoch: u64,
    binding: Mutex<Binding>,
    id: Mutex<Option<String>>,
    expiry: AtomicI64,
    state: Mutex<State>,
    task: Mutex<Option<tokio::task::AbortHandle>>,
}

impl Entry {
    pub(super) fn abort(&self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
        *self.state.lock().unwrap() = State::Consumed;
    }

    fn observe(self: &Arc<Self>, inner: &Arc<Inner>, value: &serde_json::Value) {
        if let Some(id) = value["approval_id"]
            .as_str()
            .filter(|id| crate::approval::valid_id(id))
        {
            *self.id.lock().unwrap() = Some(id.into());
        }
        let expiry = value["expires_at"]
            .as_i64()
            .unwrap_or_else(|| unix_time() + 600);
        self.expiry.store(expiry, Ordering::SeqCst);
        let weak = Arc::downgrade(self);
        let inner = Arc::downgrade(inner);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs((expiry - unix_time()).max(1) as u64)).await;
            if let Some(entry) = weak.upgrade() {
                let current = entry.expiry.load(Ordering::SeqCst);
                if current != expiry {
                    if let Some(inner) = inner.upgrade() {
                        entry.observe(&inner, &serde_json::json!({"expires_at":current}));
                    }
                    return;
                }
                entry.abort();
                if let Some(inner) = inner.upgrade() {
                    inner
                        .recoveries
                        .lock()
                        .unwrap()
                        .retain(|item| !Arc::ptr_eq(item, &entry));
                }
            }
        });
    }

    fn pending(&self) -> Response<BoxBody> {
        let id = self.id.lock().unwrap();
        match id.as_deref() {
            Some(id) => {
                crate::approval::boxed_response(crate::approval::pending_response(id).unwrap())
            }
            None => error(
                StatusCode::TOO_MANY_REQUESTS,
                "keyvalet_gateway_busy",
                "Approval creation is in progress; retry later",
                None,
            ),
        }
    }
}

fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn error(status: StatusCode, ty: &str, message: &str, id: Option<&str>) -> Response<BoxBody> {
    let mut response = crate::approval::error_response(status, ty, message, id);
    if status == StatusCode::TOO_MANY_REQUESTS {
        response.headers_mut().remove("x-should-retry");
        response
            .headers_mut()
            .insert("retry-after", "30".parse().unwrap());
    }
    crate::approval::boxed_response(response)
}

pub(super) async fn dispatch<F, Fut>(
    inner: Arc<Inner>,
    epoch: u64,
    request: crate::approval::ApprovalRequest,
    retry: Option<String>,
    layer: crate::approval::ApprovalLayer,
    hint: Option<u64>,
    forward: F,
) -> Reply
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Reply> + Send + 'static,
{
    let binding = Binding::from(&request);
    let entry = {
        let mut entries = inner.recoveries.lock().unwrap();
        entries.retain(|entry| {
            if entry.expiry.load(Ordering::SeqCst) <= unix_time() {
                entry.abort();
                false
            } else {
                true
            }
        });
        if let Some(id) = retry {
            if !crate::approval::valid_id(&id) {
                return Ok(error(
                    StatusCode::BAD_REQUEST,
                    "keyvalet_invalid_approval_id",
                    "Invalid approval_id",
                    None,
                ));
            }
            let Some(entry) = entries
                .iter()
                .find(|entry| entry.id.lock().unwrap().as_deref() == Some(&id))
            else {
                return Ok(error(
                    StatusCode::NOT_FOUND,
                    "keyvalet_approval_unknown",
                    "No retained response for this approval in this gateway session",
                    Some(&id),
                ));
            };
            if entry.epoch != epoch || *entry.binding.lock().unwrap() != binding {
                return Ok(error(
                    StatusCode::CONFLICT,
                    "keyvalet_approval_mismatch",
                    "Retry must use the same credential, method, URL, headers and exact body",
                    Some(&id),
                ));
            }
            let mut state = entry.state.lock().unwrap();
            return Ok(match std::mem::replace(&mut *state, State::Consumed) {
                State::Ready(response) => response.response(),
                State::Consumed => error(
                    StatusCode::CONFLICT,
                    "keyvalet_approval_already_consumed",
                    "This response was already claimed; the request will not execute again",
                    Some(&id),
                ),
                State::Running => {
                    *state = State::Running;
                    entry.pending()
                }
            });
        }
        // Duplicate SDK retries while a ticket is active join its approval instead of
        // racing to consume the helper's once-only forwarding permit.
        if let Some(entry) = entries.iter().find(|entry| {
            entry.epoch == epoch
                && *entry.binding.lock().unwrap() == binding
                && !matches!(*entry.state.lock().unwrap(), State::Consumed)
        }) {
            let mut state = entry.state.lock().unwrap();
            // SDK retries preserve the request but do not reflect our ID header.
            // The exact active binding can claim the retained response too.
            return Ok(match std::mem::replace(&mut *state, State::Consumed) {
                State::Ready(response) => response.response(),
                other => {
                    *state = other;
                    entry.pending()
                }
            });
        }
        if entries.len() >= MAX_TICKETS {
            if let Some(index) = entries
                .iter()
                .position(|entry| matches!(*entry.state.lock().unwrap(), State::Consumed))
            {
                entries.remove(index);
            } else {
                return Ok(error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "keyvalet_gateway_busy",
                    "The approval recovery cache is full",
                    None,
                ));
            }
        }
        let entry = Arc::new(Entry {
            epoch,
            binding: Mutex::new(binding),
            id: Mutex::new(None),
            expiry: AtomicI64::new(unix_time() + 600),
            state: Mutex::new(State::Running),
            task: Mutex::new(None),
        });
        entries.push(entry.clone());
        entry
    };
    // Even a helper that fails before returning an ID cannot leave retained request
    // data behind indefinitely. The observed exp replaces this initial deadline.
    entry.observe(
        &inner,
        &serde_json::json!({"expires_at":entry.expiry.load(Ordering::SeqCst)}),
    );
    let (sender, receiver) = oneshot::channel();
    let worker_entry = entry.clone();
    let task = tokio::spawn(async move {
        let work = async {
            let mut sender = Some(sender);
            let retained_request = request.clone();
            let decision = layer
                .authorize_observed(request, hint, |value| worker_entry.observe(&inner, value))
                .await;
            let mut decision = match decision {
                Ok(value) => value,
                Err(message) => return (sender, fail(StatusCode::BAD_GATEWAY, &message)),
            };
            if worker_entry.expiry.load(Ordering::SeqCst) <= unix_time()
                && (crate::approval::is_pending(&decision) || decision["status"] == "ok")
            {
                decision = serde_json::json!({"status":"approval_expired","approval_id":worker_entry.id.lock().unwrap().clone()});
            }
            if crate::approval::is_pending(&decision) {
                if let Some(sender) = sender.take() {
                    let _ = sender.send(Ok(worker_entry.pending()));
                }
                // The approval and original operation outlive the downstream socket and
                // its HTTP wait budget. Continue until a decision or the request's exp.
                while crate::approval::is_pending(&decision) {
                    let expiry = worker_entry.expiry.load(Ordering::SeqCst);
                    if expiry <= unix_time() {
                        decision = serde_json::json!({"status":"approval_expired"});
                        break;
                    }
                    let id = worker_entry.id.lock().unwrap().clone().unwrap();
                    if decision["relay"] == "offline" {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        decision = match crate::approval::normalize_local_result(
                            layer.provider.authorize(retained_request.clone()).await,
                        ) {
                            Ok(value) => value,
                            Err(message) => {
                                return (sender, fail(StatusCode::BAD_GATEWAY, &message))
                            }
                        };
                        if decision["approval_id"]
                            .as_str()
                            .is_some_and(|other| other != id)
                        {
                            return (
                                sender,
                                fail(
                                    StatusCode::BAD_GATEWAY,
                                    "The helper changed the pending approval ID",
                                ),
                            );
                        }
                        continue;
                    }
                    let waited = tokio::time::timeout(
                        Duration::from_secs((expiry - unix_time()) as u64),
                        layer.provider.wait(
                            id.clone(),
                            Duration::from_secs((expiry - unix_time()) as u64),
                        ),
                    )
                    .await;
                    decision = match waited {
                        Err(_) => {
                            serde_json::json!({"status":"approval_expired", "approval_id":id})
                        }
                        Ok(result) => match crate::approval::normalize_local_result(result) {
                            Ok(value) => value,
                            Err(message) => {
                                return (sender, fail(StatusCode::BAD_GATEWAY, &message))
                            }
                        },
                    };
                    if decision["approval_id"]
                        .as_str()
                        .is_some_and(|other| other != id)
                    {
                        return (
                            sender,
                            fail(
                                StatusCode::BAD_GATEWAY,
                                "The helper changed the pending approval ID",
                            ),
                        );
                    }
                    if crate::approval::is_pending(&decision) {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            if worker_entry.expiry.load(Ordering::SeqCst) <= unix_time()
                && decision["status"] == "ok"
            {
                decision = serde_json::json!({"status":"approval_expired","approval_id":worker_entry.id.lock().unwrap().clone()});
            }
            let response = match crate::approval::http_response(&decision) {
                Ok(Some(response)) => crate::approval::boxed_response(response),
                Ok(None) => match forward().await {
                    Ok(response) => response,
                    Err((status, _, message)) => fail(status, &message),
                },
                Err(error) => fail(error.status, &error.message),
            };
            (sender, response)
        };
        let (sender, mut response) = tokio::select! { biased;
            _ = inner.revoked(epoch) => { worker_entry.abort(); return; },
            result = work => result,
        };
        if let Some(id) = worker_entry.id.lock().unwrap().as_ref() {
            response
                .headers_mut()
                .insert("x-keyvalet-approval-id", id.parse().unwrap());
        }
        if let Some(sender) = sender {
            match sender.send(Ok(response)) {
                Ok(()) => {
                    *worker_entry.state.lock().unwrap() = State::Consumed;
                    return;
                }
                Err(Ok(undelivered)) => response = undelivered,
                Err(Err(_)) => unreachable!(),
            }
        }
        let retained = tokio::select! { biased;
            _ = inner.revoked(epoch) => { worker_entry.abort(); return; },
            result = Retained::collect(response) => result,
        };
        if !inner.revoked_since(epoch) && worker_entry.expiry.load(Ordering::SeqCst) > unix_time() {
            *worker_entry.state.lock().unwrap() = State::Ready(retained);
        }
    });
    *entry.task.lock().unwrap() = Some(task.abort_handle());
    receiver.await.unwrap_or_else(|_| Err(revoked_error()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::future::BoxFuture;
    use serde_json::{json, Value};
    use std::sync::atomic::AtomicUsize;

    const ID: &str = "01J00000000000000000000000";
    struct Helper {
        submitted: tokio::sync::Notify,
        expiry: i64,
    }
    impl crate::approval::ApprovalProvider for Helper {
        fn authorize(
            &self,
            _: crate::approval::ApprovalRequest,
        ) -> BoxFuture<'_, Result<Value, String>> {
            Box::pin(async {
                self.submitted.notify_one();
                Ok(json!({"status":"approval_pending","approval_id":ID,"expires_at":self.expiry}))
            })
        }
        fn wait(&self, _: String, _: Duration) -> BoxFuture<'_, Result<Value, String>> {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(json!({"status":"ok","approval_id":ID}))
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_releases_retained_payloads_and_oversized_results_never_execute_again() {
        for large in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let gateway = Gateway::new(
                Arc::new(Vault::new(dir.path().join("vault"))),
                Arc::new(|_| {}),
                None,
            );
            let helper = Arc::new(Helper {
                submitted: tokio::sync::Notify::new(),
                expiry: unix_time() + 5,
            });
            let layer = crate::approval::ApprovalLayer {
                provider: helper.clone(),
                http_wait: Duration::from_secs(2),
                notice: None,
            };
            let request = crate::approval::ApprovalRequest {
                credential_type: "api_key".into(),
                credential_name: "fixture".into(),
                method: "POST".into(),
                url: "https://example.test/once".into(),
                headers: HashMap::new(),
                body: Bytes::from_static(b"fixture"),
                purpose: None,
            };
            let inner = gateway.inner.clone();
            let original = request.clone();
            let policy = layer.clone();
            let executions = Arc::new(AtomicUsize::new(0));
            let count = executions.clone();
            let forwarded = Arc::new(tokio::sync::Notify::new());
            let notice = forwarded.clone();
            let caller = tokio::spawn(async move {
                dispatch(inner, 0, original, None, policy, None, move || async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    notice.notify_one();
                    Ok(Response::new(full_body(vec![
                        0;
                        if large {
                            MAX_RETAINED_BODY + 1
                        } else {
                            64
                        }
                    ])))
                })
                .await
            });
            helper.submitted.notified().await;
            caller.abort();
            assert!(caller.await.unwrap_err().is_cancelled());
            let weak = Arc::downgrade(&gateway.inner.recoveries.lock().unwrap()[0]);
            tokio::time::advance(Duration::from_secs(2)).await;
            forwarded.notified().await;
            if large {
                let response = dispatch(
                    gateway.inner.clone(),
                    0,
                    request.clone(),
                    Some(ID.into()),
                    layer.clone(),
                    None,
                    || async { panic!("A retained result must not execute again") },
                )
                .await
                .unwrap();
                assert_eq!(response.status(), 502);
                assert_eq!(response.headers()["x-should-retry"], "false");
                let value: Value = serde_json::from_slice(
                    &response.into_body().collect().await.unwrap().to_bytes(),
                )
                .unwrap();
                assert_eq!(value["error"]["type"], "keyvalet_response_unavailable");
            } else {
                assert!(matches!(
                    *weak.upgrade().unwrap().state.lock().unwrap(),
                    State::Ready(_)
                ));
            }
            tokio::time::advance(Duration::from_secs(6)).await;
            tokio::task::yield_now().await;
            assert!(
                weak.upgrade().is_none(),
                "exp must release the entry and its zeroizing payload"
            );
            let response = dispatch(
                gateway.inner.clone(),
                0,
                request,
                Some(ID.into()),
                layer,
                None,
                || async { panic!("An expired ID must not create another approval") },
            )
            .await
            .unwrap();
            assert_eq!(response.status(), 404);
            assert_eq!(executions.load(Ordering::SeqCst), 1);
        }
    }
}
