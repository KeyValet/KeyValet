//! Regression coverage for the six integration review findings.
use super::boundaries::signing_harness;
use super::*;

#[tokio::test]
async fn legacy_grants_respect_pairing_exclusions_without_blocking_explicit_device_grants() {
    let h = signing_harness();
    h.helper
        .lock()
        .unwrap()
        .store
        .set_setting(
            &format!("global_excluded:{}", h.peer.device_id),
            &true,
            "local",
            h.clock.now(),
        )
        .unwrap();
    let mut grant = super::workflow::signed_grant(&h, "legacy", Tier::T1, 10);
    grant.iss = h.helper.local.device_id.clone();
    grant.aud = "*".into();
    grant.scope.level = GrantScopeLevel::Global;
    let request = serde_json::to_value(kv_core::remote::ipc::Unsigned(grant.clone())).unwrap();
    assert_eq!(
        h.exchange(Caller::CliOwner, Op::GrantIssue, request).await["error"]["code"],
        "wrong_recipient"
    );
    assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
    grant.aud = h.peer.device_id.clone();
    grant.scope.level = GrantScopeLevel::Credential;
    let request = serde_json::to_value(kv_core::remote::ipc::Unsigned(grant)).unwrap();
    assert_eq!(
        h.exchange(Caller::CliOwner, Op::GrantIssue, request).await["ok"],
        true
    );
    assert_eq!(h.helper.outbound_poll(0).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_previous_pairing_confirmation_cannot_cancel_the_current_pairing() {
    let h = Harness::with(Store::memory().unwrap(), 1_800_000_000, false);
    let started = h.helper.pair_start("https://relay.example.com").unwrap();
    let sas = h
        .helper
        .pair_complete(PairAccept {
            token: started.extra["token"].as_str().unwrap().into(),
            joiner: h.peer.clone(),
            extra: Extra::new(),
        })
        .unwrap()
        .sas;
    h.helper.lock().unwrap().pairing.as_mut().unwrap().transport =
        Some(super::super::pairing_relay::PairTransport {
            relay: super::super::pairing_relay::RelayApi::new("https://relay.example.com").unwrap(),
            pairing_id: "current-pairing".into(),
            joiner: false,
        });
    let confirmation = PairConfirm {
        sas: sas.clone(),
        sig: String::new(),
        extra: Extra::new(),
    };
    assert_eq!(
        h.helper
            .inbound(h.envelope(EnvelopeType::PairConfirm, "previous-pairing", &confirmation))
            .await
            .unwrap_err()
            .code(),
        "wrong_pairing"
    );
    assert_eq!(
        h.helper.pairing_status(&h.helper.lock().unwrap()).unwrap()["sas"],
        sas
    );
}

#[tokio::test]
async fn grant_pages_have_no_gaps_duplicates_or_oversized_envelopes() {
    let h = signing_harness();
    let mut expected = std::collections::HashSet::new();
    for index in 0..125 {
        let hosts = if index == 124 {
            Some(
                (0..850)
                    .map(|n| format!("h{n}.{}.example.com", "a".repeat(40)))
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };
        let result=h.exchange(Caller::CliOwner,Op::GrantIssue,json!({"source":"settings","kind":"grant","aud":h.peer.device_id,
            "scope":{"level":"device","max_tier":"T1","hosts":hosts},"nbf":0,"exp":null,"origin":"settings"})).await;
        assert_eq!(result["ok"], true, "{result}");
        expected.insert(
            result["result"]["grant"]["jti"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let mut cursor = None;
    let mut actual = std::collections::HashSet::new();
    let mut summary = false;
    loop {
        let page = h
            .exchange(
                Caller::CliOwner,
                Op::GrantList,
                json!({"after":cursor,"limit":17}),
            )
            .await;
        assert_eq!(page["ok"], true, "{page}");
        assert!(serde_json::to_vec(&page).unwrap().len() < 50 * 1024);
        for grant in page["result"]["grants"].as_array().unwrap() {
            assert!(actual.insert(grant["jti"].as_str().unwrap().to_owned()));
            if grant["object_omitted"] == true {
                summary = true;
                assert!(grant.get("sig").is_none());
            }
        }
        cursor = page["result"]["next_cursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(actual, expected);
    assert!(summary);
    assert_eq!(
        h.exchange(Caller::CliOwner, Op::GrantList, json!({"limit":0}))
            .await["error"]["code"],
        "invalid_page"
    );
}

#[tokio::test]
async fn a_dk_signature_cannot_authorize_revocation_and_strong_proofs_are_account_bound() {
    let h = Harness::new();
    let proof = kv_core::remote::relay::DeviceDeleteProof {
        action: kv_core::remote::relay::DeviceDeleteAction::RevokeDevice,
        account: h.helper.account.clone(),
        by: h.peer.device_id.clone(),
        device_id: h.peer.device_id.clone(),
        challenge: kv_core::remote::keys::encode_b64(&[4; 32]),
        extra: Extra::new(),
    };
    let sig = sign_object(&proof, SignatureAlgorithm::ES256, key("strong").as_ref()).unwrap();
    let mut body = DeviceRevoke {
        device_id: h.peer.device_id.clone(),
        extra: json!({"proof":proof,"sig":sig})
            .as_object()
            .unwrap()
            .clone(),
    };
    let mut quick = body.clone();
    quick.extra["sig"] =
        json!(sign_object(&proof, SignatureAlgorithm::ES256, key("quick").as_ref()).unwrap());
    assert!(
        kv_core::remote::validation::verify_device_revoke(&quick, &h.peer, &h.helper.account)
            .is_err()
    );
    assert!(
        kv_core::remote::validation::verify_device_revoke(&body, &h.peer, "another-account")
            .is_err()
    );
    body.device_id = "another-device".into();
    assert!(
        kv_core::remote::validation::verify_device_revoke(&body, &h.peer, &h.helper.account)
            .is_err()
    );
    let bare = DeviceRevoke {
        device_id: h.peer.device_id.clone(),
        extra: Extra::new(),
    };
    assert!(h
        .helper
        .inbound(h.envelope(EnvelopeType::DeviceRevoke, "bare", &bare))
        .await
        .is_err());
    assert!(h
        .helper
        .lock()
        .unwrap()
        .store
        .device(&h.peer.device_id, &h.helper.account)
        .is_ok());
}
