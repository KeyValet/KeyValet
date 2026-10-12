//! Helper-side relay control bridge. All HTTP, WS and session-token handling lives in the
//! unprivileged relay client. This module only queues typed requests and consumes their replies.
use super::{Error, Result};
use kv_core::remote::keys::encode_b64;
use kv_core::remote::relay::*;
use kv_core::remote::relay_control::*;
use kv_core::remote::*;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use url::Url;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct RelayApi {
    pub url: Url,
    hub: Arc<super::relay_control::ControlHub>,
    #[cfg(test)]
    pub(crate) transport: kv_relay_client::control_transport::RelayApi,
    accounts: Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>,
}
impl RelayApi {
    pub fn new(url: &str) -> Result<Self> {
        let url = Url::parse(url).map_err(|_| Error("invalid_relay_url"))?;
        let loopback = url
            .host_str()
            .and_then(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback());
        if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || (url.scheme() == "https" && url.port_or_known_default() != Some(443))
        {
            return Err(Error("invalid_relay_url"));
        }
        #[cfg(not(test))]
        let hub = super::relay_control::hub();
        #[cfg(test)]
        let (hub, transport) = super::tests::control_transport::test_hub(url.as_str());
        Ok(Self {
            url,
            hub,
            #[cfg(test)]
            transport,
            accounts: Arc::new(tokio::sync::Mutex::new(Default::default())),
        })
    }
    pub async fn post<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        path: &str,
        value: &T,
        device: Option<&str>,
    ) -> Result<R> {
        let value = serde_json::to_value(value)?;
        let command = match path {
            "v1/devices" => RelayControlCommand::Register(serde_json::from_value(value)?),
            "v1/recovery" => RelayControlCommand::RecoverAccount(serde_json::from_value(value)?),
            "v1/pair/start" => RelayControlCommand::PairStart(serde_json::from_value(value)?),
            "v1/pair/complete" => RelayControlCommand::PairComplete(serde_json::from_value(value)?),
            "v1/pair/finish" => RelayControlCommand::PairFinish(serde_json::from_value(value)?),
            "v1/messages" => RelayControlCommand::Messages(serde_json::from_value(value)?),
            "v1/messages/ack" => RelayControlCommand::Ack(serde_json::from_value(value)?),
            "v1/auth/challenge" => RelayControlCommand::Challenge(serde_json::from_value(value)?),
            _ => return Err(Error("forbidden")),
        };
        let result = self
            .hub
            .submit(
                self.url.to_string(),
                device.map(str::to_owned),
                command,
                None,
            )
            .await?;
        let value = match result {
            RelayControlResult::Registered(value) => serde_json::to_value(value)?,
            RelayControlResult::Recovered(value) => serde_json::to_value(value)?,
            RelayControlResult::PairStarted(value) => serde_json::to_value(value)?,
            RelayControlResult::PairCompleted(value) => serde_json::to_value(value)?,
            RelayControlResult::Accepted(value) => serde_json::to_value(value)?,
            RelayControlResult::Ok(value) => serde_json::to_value(value)?,
            RelayControlResult::Challenge(value) => serde_json::to_value(value)?,
            _ => return Err(Error("invalid_remote_response")),
        };
        Ok(serde_json::from_value(value)?)
    }
    pub async fn authenticate(
        &self,
        local: &DeviceRecord,
        identity: super::bootstrap::DeviceKey,
    ) -> Result<Zeroizing<String>> {
        let result = self
            .hub
            .submit(
                self.url.to_string(),
                None,
                RelayControlCommand::Authenticate(local.clone()),
                Some(identity),
            )
            .await?;
        let RelayControlResult::Authenticated { account_id } = result else {
            return Err(Error("invalid_remote_response"));
        };
        if account_id.is_empty()
            || account_id.len() > 256
            || account_id.chars().any(char::is_control)
        {
            return Err(Error("invalid_remote_response"));
        }
        self.accounts
            .lock()
            .await
            .insert(local.device_id.clone(), account_id);
        // This public device ID selects the relay client's session. It is not a bearer token.
        Ok(Zeroizing::new(local.device_id.clone()))
    }
    pub async fn account(&self, device: &str) -> Result<String> {
        self.accounts
            .lock()
            .await
            .get(device)
            .cloned()
            .ok_or(Error("invalid_remote_response"))
    }
    pub async fn pending(&self, device: &str) -> Result<Vec<Envelope>> {
        let result = self
            .hub
            .submit(
                self.url.to_string(),
                Some(device.into()),
                RelayControlCommand::Pending,
                None,
            )
            .await?;
        match result {
            RelayControlResult::Pending(envelopes) => Ok(envelopes),
            _ => Err(Error("invalid_remote_response")),
        }
    }
    pub async fn delete_device(
        &self,
        id: &str,
        device: &str,
        challenge: &str,
        sig: &str,
    ) -> Result<()> {
        self.hub
            .submit(
                self.url.to_string(),
                Some(device.into()),
                RelayControlCommand::DeleteDevice {
                    device_id: id.into(),
                    challenge: challenge.into(),
                    sig: sig.into(),
                },
                None,
            )
            .await?;
        Ok(())
    }
}

pub(crate) fn parse_uri(uri: &str) -> Result<(RelayApi, Zeroizing<Vec<u8>>)> {
    let url = Url::parse(uri).map_err(|_| Error("invalid_pair_uri"))?;
    if url.scheme() != "kv-pair"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error("invalid_pair_uri"));
    }
    let authority = &uri["kv-pair://".len()..]
        .split('/')
        .next()
        .ok_or(Error("invalid_pair_uri"))?;
    let host = url.host_str().ok_or(Error("invalid_pair_uri"))?;
    let loopback = host
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback());
    let relay = RelayApi::new(&format!(
        "{}://{authority}",
        if loopback && url.port().is_some() {
            "http"
        } else {
            "https"
        }
    ))?;
    let text = url
        .path()
        .strip_prefix('/')
        .ok_or(Error("invalid_pair_uri"))?;
    let mut token = Zeroizing::new(Vec::new());
    let mut bits = 0u32;
    let mut remaining = 0u32;
    for byte in text.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(Error("invalid_pair_uri")),
        };
        bits = (bits << 5) | u32::from(digit);
        remaining += 5;
        if remaining >= 8 {
            remaining -= 8;
            token.push((bits >> remaining) as u8);
        }
    }
    if token.len() != 16 || super::pairing::base32(&token) != text {
        return Err(Error("invalid_pair_uri"));
    }
    Ok((relay, token))
}

pub(crate) struct Registration {
    pub relay: RelayApi,
    pub join_token: Option<Zeroizing<Vec<u8>>>,
    pub joined: std::sync::Mutex<Option<PairCompleteResponse>>,
    pub runtime: tokio::runtime::Handle,
}

impl super::bootstrap::Registrar for Registration {
    fn register(&self, local: &DeviceRecord) -> Result<RegisterDeviceResponse> {
        self.runtime.block_on(async {
            if let Some(token) = &self.join_token {
                let response: PairCompleteResponse = self
                    .relay
                    .post(
                        "v1/pair/complete",
                        &PairCompleteRequest {
                            token: encode_b64(token),
                            joiner: local.clone(),
                            extra: Extra::new(),
                        },
                        None,
                    )
                    .await?;
                let account = response
                    .account_id
                    .as_value()
                    .cloned()
                    .ok_or(Error("invalid_remote_response"))?;
                *self.joined.lock().map_err(|_| Error("state_unavailable"))? = Some(response);
                Ok(RegisterDeviceResponse {
                    account_id: account,
                    device_id: local.device_id.clone(),
                    recovery_code: Optional::Missing,
                    extra: Extra::new(),
                })
            } else {
                self.relay
                    .post(
                        "v1/devices",
                        &RegisterDeviceRequest {
                            device: local.clone(),
                            push_token: Optional::Missing,
                        },
                        None,
                    )
                    .await
            }
        })
    }
}

#[derive(Clone)]
pub(crate) struct PairTransport {
    pub relay: RelayApi,
    pub pairing_id: String,
    pub joiner: bool,
}

impl super::RemoteHelper {
    pub(crate) fn start_pair_poll(self: &Arc<Self>, relay: RelayApi) {
        let pairing_id = self.lock().ok().and_then(|state| {
            state
                .pairing
                .as_ref()
                .and_then(|pairing| pairing.transport.as_ref())
                .map(|transport| transport.pairing_id.clone())
        });
        let Some(pairing_id) = pairing_id else {
            return;
        };
        let helper = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut session = None;
            loop {
                let Some(helper) = helper.upgrade() else {
                    return;
                };
                let active = helper.lock().is_ok_and(|state| {
                    state.pairing.as_ref().is_some_and(|pairing| {
                        pairing.exp >= helper.services.clock.now()
                            && pairing
                                .transport
                                .as_ref()
                                .is_some_and(|transport| transport.pairing_id == pairing_id)
                    })
                });
                if !active {
                    return;
                }
                // CONTRACT: §9.1 / Appendix B: the relay-client owns the live device socket.
                if helper.lock().is_ok_and(|state| state.relay_connected) {
                    drop(helper);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                let result = async {
                    if session.is_none() {
                        session = Some(
                            relay
                                .authenticate(&helper.local, helper.services.identity.clone())
                                .await?,
                        );
                    }
                    let session = session.as_deref().ok_or(Error("unauthorized"))?;
                    for envelope in relay.pending(session).await? {
                        if !matches!(
                            envelope.r#type,
                            EnvelopeType::PairAccept | EnvelopeType::PairConfirm
                        ) || envelope.id != pairing_id
                        {
                            continue;
                        }
                        let id = envelope.id.clone();
                        let kind = envelope.r#type.as_str().to_owned();
                        helper.inbound(envelope).await?;
                        let _: OkResponse = relay
                            .post(
                                "v1/messages/ack",
                                &AckMessagesRequest {
                                    ids: vec![id],
                                    kind: Optional::Value(kind),
                                    extra: Extra::new(),
                                },
                                Some(session),
                            )
                            .await?;
                    }
                    Ok::<_, Error>(())
                }
                .await;
                if let Err(error) = result {
                    session = None;
                    if matches!(
                        error.code(),
                        "pair_sas_mismatch" | "replay" | "expired" | "forbidden"
                    ) {
                        if let Ok(mut state) = helper.lock() {
                            if state
                                .pairing
                                .as_ref()
                                .and_then(|pairing| pairing.transport.as_ref())
                                .is_some_and(|transport| transport.pairing_id == pairing_id)
                            {
                                let _ = helper.pair_failed(&mut state, error);
                            }
                        }
                        return;
                    }
                }
                drop(helper);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }
}
