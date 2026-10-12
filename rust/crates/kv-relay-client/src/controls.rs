//! Typed control dispatch; the caller supplies only a job-scoped challenge-signing callback.
use crate::{control_transport::RelayApi, Error, Result};
use kv_core::remote::{relay::*, relay_control::*};

pub async fn execute<F, Fut>(relay: &RelayApi, job: &RelayControlJob, sign: F) -> RelayControlResult
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    let result = execute_inner(relay, job, sign).await.and_then(|result| {
        if matches!(&result, RelayControlResult::Ok(value) if !value.ok)
            || matches!((&job.command, &result), (RelayControlCommand::Messages(request), RelayControlResult::Accepted(value))
                if value.accepted != request.envelopes.len() as u64) {
            Err(Error("invalid_remote_response"))
        } else { Ok(result) }
    });
    result
        .unwrap_or_else(|error| RelayControlResult::Failure(RelayControlError::from_code(error.0)))
}
async fn execute_inner<F, Fut>(
    relay: &RelayApi,
    job: &RelayControlJob,
    sign: F,
) -> Result<RelayControlResult>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    use RelayControlCommand as C;
    use RelayControlResult as R;
    if relay.url.as_str() != job.relay_url {
        return Err(Error("invalid_relay_url"));
    }
    let token = match job.device_id.as_deref() {
        Some(device) => Some(relay.session(device).await?),
        None => None,
    };
    let token = token.as_deref().map(String::as_str);
    Ok(match &job.command {
        C::Authenticate(local) => {
            relay.authenticate(local, sign).await?;
            R::Authenticated {
                account_id: relay.account(&local.device_id).await?,
            }
        }
        C::Register(value) => R::Registered(relay.post("v1/devices", value, token).await?),
        C::RecoverAccount(value) => R::Recovered(relay.recover_account(value).await?),
        C::PairStart(value) => R::PairStarted(relay.post("v1/pair/start", value, token).await?),
        C::PairComplete(value) => {
            R::PairCompleted(relay.post("v1/pair/complete", value, token).await?)
        }
        C::PairFinish(value) => R::Ok(relay.post("v1/pair/finish", value, token).await?),
        C::Messages(value) => R::Accepted(relay.post("v1/messages", value, token).await?),
        C::Ack(value) => R::Ok(relay.post("v1/messages/ack", value, token).await?),
        C::Challenge(value) => R::Challenge(relay.post("v1/auth/challenge", value, token).await?),
        C::Pending => R::Pending(relay.pending(token.ok_or(Error("unauthorized"))?).await?),
        C::DeleteDevice {
            device_id,
            challenge,
            sig,
        } => {
            relay
                .delete_device(
                    device_id,
                    token.ok_or(Error("unauthorized"))?,
                    challenge,
                    sig,
                )
                .await?;
            R::Ok(OkResponse {
                ok: true,
                extra: Default::default(),
            })
        }
    })
}
