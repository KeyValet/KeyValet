use super::boundaries::signing_harness;
use super::*;

fn draft(h: &Harness) -> Value {
    json!({"source":"settings","kind":"grant","aud":h.peer.device_id,
        "scope":{"level":"device","max_tier":"T2"},"nbf":h.clock.now(),
        "exp":h.clock.now()+3600,"origin":"settings"})
}

#[tokio::test]
async fn owner_t2_intent_requires_strong_then_one_use_label_proof() {
    let h = signing_harness();
    let mut intent = draft(&h);
    let prepared = h
        .exchange(Caller::CliOwner, Op::GrantIssue, intent.clone())
        .await;
    assert_eq!(prepared["ok"], true);
    assert_eq!(prepared["result"]["label"], h.peer.label);
    assert_eq!(prepared["result"]["expires_at"], h.clock.now() + 120);
    assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
    intent["confirm"] = prepared["result"]["label"].clone();
    intent["confirmation_token"] = prepared["result"]["confirmation_token"].clone();
    let issued = h
        .exchange(Caller::CliOwner, Op::GrantIssue, intent.clone())
        .await;
    assert_eq!(issued["ok"], true);
    let grant: Grant = serde_json::from_value(issued["result"]["grant"].clone()).unwrap();
    kv_core::remote::validation::verify_grant(
        &grant,
        &h.peer.device_id,
        &h.peer.label,
        &h.helper.local,
        ApprovalLevel::Strong,
        h.clock.now(),
    )
    .unwrap();
    assert_eq!(grant.confirm.as_value(), Some(&h.peer.label));
    let replay = h.exchange(Caller::CliOwner, Op::GrantIssue, intent).await;
    assert_eq!(replay["error"]["code"], "secondary_confirmation_required");
}

#[tokio::test]
async fn owner_t2_proof_binds_draft_caller_label_and_expiration() {
    for variant in 0..6 {
        let h = signing_harness();
        let mut intent = draft(&h);
        let prepared = h
            .exchange(Caller::CliOwner, Op::GrantIssue, intent.clone())
            .await;
        intent["confirm"] = prepared["result"]["label"].clone();
        intent["confirmation_token"] = prepared["result"]["confirmation_token"].clone();
        let mut uid = 501;
        let mut pid = 4242;
        match variant {
            0 => intent["confirm"] = json!("another label"),
            1 => intent["exp"] = json!(h.clock.now() + 1800),
            2 => uid += 1,
            3 => pid += 1,
            4 => {
                h.clock.0.fetch_add(120, Ordering::SeqCst);
            }
            _ => intent["iss"] = json!("caller-chosen-issuer"),
        }
        let response = serde_json::to_value(
            h.helper
                .handle(
                    CallerContext::authenticated(Caller::CliOwner, uid, pid, 50),
                    Request {
                        op: Op::GrantIssue,
                        params: intent,
                        extra: Extra::new(),
                    },
                )
                .await,
        )
        .unwrap();
        assert_eq!(response["ok"], false);
        assert_eq!(
            response["error"]["code"],
            if variant == 5 {
                "invalid_json"
            } else {
                "secondary_confirmation_required"
            }
        );
        assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
    }
    let h = signing_harness();
    *h.runner.level.lock().unwrap() = ApprovalLevel::Quick;
    let response = h
        .exchange(Caller::CliOwner, Op::GrantIssue, draft(&h))
        .await;
    assert_eq!(response["error"]["code"], "insufficient_level");
    assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
}

#[test]
fn pairing_http_api_rejects_ambiguous_origins_and_noncanonical_tokens() {
    use super::super::pairing_relay::{parse_uri, RelayApi};
    for url in ["https://relay.example.com", "http://127.0.0.1:8787"] {
        assert!(RelayApi::new(url).is_ok());
    }
    for url in [
        "http://relay.example.com",
        "https://relay.example.com:8443",
        "https://user@relay.example.com",
        "https://relay.example.com/path",
        "https://relay.example.com/?secret=value",
        "https://relay.example.com/#fragment",
    ] {
        assert!(RelayApi::new(url).is_err());
    }
    let uri = "kv-pair://relay.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAA";
    let (_, token) = parse_uri(uri).unwrap();
    assert_eq!(token.len(), 16);
    for value in [
        "kv-pair://relay.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAB",
        "kv-pair://relay.example.com/aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "kv-pair://relay.example.com/AA",
        "kv-pair://user@relay.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "kv-pair://relay.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAA?extra=true",
    ] {
        assert!(parse_uri(value).is_err());
    }
}
