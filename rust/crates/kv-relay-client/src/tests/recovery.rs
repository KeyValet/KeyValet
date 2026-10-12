use crate::control_transport::RelayApi;
use kv_core::remote::{
    keys::{decode_b64, encode_b64},
    relay::*,
    *,
};

fn device(key: &SoftwareDeviceKey, id: &str) -> DeviceRecord {
    DeviceRecord {
        device_id: id.into(),
        label: id.into(),
        os: Os::Linux,
        key_kind: KeyKind::Software,
        dk_pub: key.public_jwk().unwrap(),
        dk_sig: kv_core::remote::Optional::Missing,
        ak_q: None,
        ak_s: None,
        caps: vec![Capability::Execute],
        attestation: None,
        extra: Extra::new(),
    }
}

#[tokio::test]
async fn signed_recovery_client_replaces_an_account_and_forgets_cached_old_sessions() {
    let (url, server) = kv_server::spawn_test_relay();
    let api = RelayApi::new(url.as_str()).unwrap();
    let old_key = SoftwareDeviceKey::generate_p256();
    let old = device(&old_key, "old");
    let registered: RegisterDeviceResponse = api
        .post(
            "v1/devices",
            &RegisterDeviceRequest {
                device: old.clone(),
                push_token: Optional::Missing,
            },
            None,
        )
        .await
        .unwrap();
    api.authenticate(&old, |challenge| async move {
        Ok(encode_b64(&DeviceKeyProvider::sign(
            &old_key,
            SignatureAlgorithm::ES256,
            &decode_b64(&challenge)?,
        )?))
    })
    .await
    .unwrap();
    let key = SoftwareDeviceKey::generate_p256();
    let new = device(&key, "new");
    let request = RecoverAccountRequest::signed(
        registered.account_id.clone(),
        registered.recovery_code.as_value().unwrap().clone(),
        new.clone(),
        &key,
    )
    .unwrap();
    // The caller can save this before sending, so losing the HTTP response cannot lose it.
    let saved = request.new_recovery_code.clone();
    let response = api.recover_account(&request).await.unwrap();
    assert_eq!(response.recovery_code, saved);
    assert!(api.session(&old.device_id).await.is_err());
    assert!(api.account(&old.device_id).await.is_err());
    api.authenticate(&new, |challenge| async move {
        Ok(encode_b64(&DeviceKeyProvider::sign(
            &key,
            SignatureAlgorithm::ES256,
            &decode_b64(&challenge)?,
        )?))
    })
    .await
    .unwrap();
    assert_eq!(
        api.account(&new.device_id).await.unwrap(),
        registered.account_id
    );
    assert!(api.recover_account(&request).await.is_err());
    server.shutdown().await;
}
