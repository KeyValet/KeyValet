//! Test adapter runs the production relay-client transport, with an injected helper control
//! boundary. It needs no installed binary, privileged identity or live daemon.
use super::super::relay_control::ControlHub;
use kv_core::remote::relay_control::*;
use std::sync::Arc;

pub fn test_hub(
    url: &str,
) -> (
    Arc<ControlHub>,
    kv_relay_client::control_transport::RelayApi,
) {
    let hub = Arc::new(ControlHub::default());
    let transport = kv_relay_client::control_transport::RelayApi::new(url).unwrap();
    let relay = transport.clone();
    let weak = Arc::downgrade(&hub);
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(async move {
            loop {
                let Some(hub) = weak.upgrade() else {
                    return;
                };
                let Some(job) = hub
                    .poll(RelayControlPollParams { max_wait_ms: 100 })
                    .await
                    .expect("control poll")
                    .request
                else {
                    continue;
                };
                let result = kv_relay_client::controls::execute(&relay, &job, |challenge| async {
                    let result = hub
                        .sign(RelayControlSignParams {
                            id: job.id.clone(),
                            payload_b64: challenge,
                        })
                        .map_err(|error| kv_relay_client::Error(error.code()))?;
                    Ok(result["sig_b64"].as_str().unwrap().to_owned())
                })
                .await;
                let _ = hub.complete(RelayControlCompleteParams { id: job.id, result });
            }
        });
    }
    (hub, transport)
}

#[tokio::test]
async fn control_role_is_rejected_for_every_other_caller() {
    use kv_ipc::remote::{Caller, Op};
    for role in [
        Caller::Mcp,
        Caller::Hook,
        Caller::CliOwner,
        Caller::ApprovalAgent,
    ] {
        for op in [
            Op::RelayControlPoll,
            Op::RelayControlComplete,
            Op::RelayControlSign,
        ] {
            let response =
                super::super::relay_control::handle(role, op, serde_json::json!({})).await;
            assert_eq!(
                serde_json::to_value(response).unwrap()["error"]["code"],
                "forbidden"
            );
        }
    }
}

#[tokio::test]
async fn request_bound_signing_and_completion_reject_replay_and_wrong_shape() {
    use kv_core::remote::keys::{encode_b64, SoftwareDeviceKey};
    let hub = Arc::new(ControlHub::default());
    let key = Arc::new(SoftwareDeviceKey::generate_p256());
    let mut device = super::Harness::new().helper.local.clone();
    device.dk_pub = kv_core::remote::keys::DeviceKeyProvider::public_jwk(key.as_ref()).unwrap();
    let submitted = hub.clone();
    let task = tokio::spawn(async move {
        submitted
            .submit(
                "https://relay.example.com/".into(),
                None,
                RelayControlCommand::Authenticate(device),
                Some(key),
            )
            .await
    });
    let job = hub
        .poll(RelayControlPollParams { max_wait_ms: 1000 })
        .await
        .unwrap()
        .request
        .unwrap();
    assert!(hub
        .sign(RelayControlSignParams {
            id: job.id.clone(),
            payload_b64: encode_b64(&[1; 31])
        })
        .is_err());
    let signed = hub
        .sign(RelayControlSignParams {
            id: job.id.clone(),
            payload_b64: encode_b64(&[1; 32]),
        })
        .unwrap();
    assert_eq!(
        signed,
        hub.sign(RelayControlSignParams {
            id: job.id.clone(),
            payload_b64: encode_b64(&[1; 32])
        })
        .unwrap()
    );
    assert_eq!(
        hub.sign(RelayControlSignParams {
            id: job.id.clone(),
            payload_b64: encode_b64(&[2; 32])
        })
        .unwrap_err()
        .code(),
        "identity_challenge_changed"
    );
    assert_eq!(
        hub.complete(RelayControlCompleteParams {
            id: job.id.clone(),
            result: RelayControlResult::Ok(kv_core::remote::relay::OkResponse {
                ok: true,
                extra: Default::default()
            })
        })
        .unwrap_err()
        .code(),
        "invalid_control_result"
    );
    hub.complete(RelayControlCompleteParams {
        id: job.id.clone(),
        result: RelayControlResult::Authenticated {
            account_id: "account".into(),
        },
    })
    .unwrap();
    assert!(task.await.unwrap().is_ok());
    assert!(hub
        .sign(RelayControlSignParams {
            id: job.id.clone(),
            payload_b64: encode_b64(&[1; 32])
        })
        .is_err());
    assert!(hub
        .complete(RelayControlCompleteParams {
            id: job.id,
            result: RelayControlResult::Authenticated {
                account_id: "account".into()
            }
        })
        .is_err());
}
