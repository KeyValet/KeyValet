use super::*;

#[test]
fn five_minute_skew_in_either_direction_is_visible_in_app_and_native_notification() {
    let f = Fixture::new();
    for offset in [-300, 300] {
        let (request, _) = f.request(Tier::T1);
        let mut header = f
            .envelope(
                EnvelopeType::ApprovalRequest,
                &request.approval_id,
                &request,
                request.exp,
            )
            .header();
        header.created_at = now() + offset;
        let envelope = remote::envelope::seal(
            header,
            &jcs(&request).unwrap(),
            &f.core.device().dk_pub,
            f.executor.as_ref(),
        )
        .unwrap();
        let notification = f
            .core
            .receive(&serde_json::to_vec(&envelope).unwrap())
            .unwrap()
            .unwrap();
        assert!(notification.body.contains("Device clock differs"));
        assert!(notification.body.contains(&request.agent.cwd));
        assert!(notification
            .body
            .contains(request.credential.as_ref().unwrap().r#ref.as_str()));
        assert!(
            f.core
                .snapshot()
                .unwrap()
                .pending
                .iter()
                .find(|view| view.id == request.approval_id)
                .unwrap()
                .clock_skew
        );
    }
}

#[tokio::test]
async fn offline_logout_retries_remote_token_removal_and_sign_in_reuploads_the_same_token() {
    let f = Fixture::new();
    let issuer = accounts::issuer();
    let (base, server) = accounts::server(&issuer);
    f.core
        .store
        .transaction(|db| Store::delete(db, "peers", &f.peer.device_id))
        .unwrap();
    f.core.set_relay(base.as_str()).unwrap();
    f.core.require_account_login();
    let relay = Relay::new(f.core.clone()).unwrap();
    let push = json!({"platform":"apns","token":"a".repeat(64)});
    f.core
        .store
        .transaction(|db| f.core.store.put(db, "meta", "push_token", &push, 0))
        .unwrap();
    let attempt = relay.account_begin("google").await.unwrap();
    relay
        .account_finish(
            &attempt.attempt_id,
            &accounts::token(&issuer, "google", "push-owner", "", now()),
            "",
            "",
        )
        .await
        .unwrap();
    let stored = || {
        server.inspect(|db| {
            db.query_row(
                "SELECT push_token FROM devices WHERE id=?1",
                [&f.core.device().device_id],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .unwrap()
        })
    };
    assert_eq!(
        serde_json::from_slice::<Value>(&stored().unwrap()).unwrap(),
        push
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let offline = format!("http://{}/", listener.local_addr().unwrap());
    drop(listener);
    f.core
        .store
        .transaction(|db| {
            let mut settings: SettingsView = f.core.store.get(db, "meta", "settings")?.unwrap();
            settings.relay_url = offline;
            f.core.store.put(db, "meta", "settings", &settings, 0)
        })
        .unwrap();
    relay.account_logout().await.unwrap();
    assert_eq!(f.core.snapshot(), Err(Error("login_required")));
    assert!(stored().is_some());
    assert_eq!(
        f.core
            .store
            .transaction(|db| f
                .core
                .store
                .list::<crate::account::Session>(db, "logout_pending"))
            .unwrap()
            .len(),
        1
    );
    f.core.set_relay(base.as_str()).unwrap();
    relay.retry_logouts().await.unwrap();
    assert!(stored().is_none());
    let attempt = relay.account_begin("google").await.unwrap();
    relay
        .account_finish(
            &attempt.attempt_id,
            &accounts::token(&issuer, "google", "push-owner", "", now()),
            "",
            "",
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&stored().unwrap()).unwrap(),
        push
    );
    server.shutdown().await;
}

#[tokio::test]
async fn cache_fallback_requests_native_retry_and_does_not_claim_live_synchronization() {
    let f = Fixture::new();
    let (request, _) = f.request(Tier::T1);
    f.receive(
        EnvelopeType::ApprovalRequest,
        &request.approval_id,
        &request,
        request.exp,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let offline = format!("http://{}/", listener.local_addr().unwrap());
    drop(listener);
    f.core
        .store
        .transaction(|db| {
            let mut settings: SettingsView = f.core.store.get(db, "meta", "settings")?.unwrap();
            settings.relay_url = offline;
            f.core.store.put(db, "meta", "settings", &settings, 0)
        })
        .unwrap();
    let (plans, retry) = Relay::new(f.core.clone())
        .unwrap()
        .sync_background_status()
        .await
        .unwrap();
    assert!(retry);
    assert_eq!(plans[0].approval_id, request.approval_id);
}

#[tokio::test]
async fn https_recovers_a_new_approval_even_when_websocket_upgrade_is_unavailable() {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let f = Fixture::new();
    let (request, _) = f.request(Tier::T1);
    let envelope = f.envelope(
        EnvelopeType::ApprovalRequest,
        &request.approval_id,
        &request,
        request.exp,
    );
    let waiting = json!({"envelopes":[envelope]}).to_string();
    let challenge = json!({"challenge":encode_b64(&[7_u8;32]),"exp":now()+60}).to_string();
    let authenticated = json!({"session_token":"ci-device-session","exp":now()+300}).to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    f.core
        .store
        .transaction(|db| {
            let mut settings: SettingsView = f.core.store.get(db, "meta", "settings")?.unwrap();
            settings.relay_url = base;
            f.core.store.put(db, "meta", "settings", &settings, 0)
        })
        .unwrap();
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..5 {
            let (socket, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let mut socket = BufReader::new(socket);
            let mut first = String::new();
            socket.read_line(&mut first).await.unwrap();
            let mut length = 0;
            let mut header_bytes = 0;
            loop {
                let mut line = String::new();
                assert!(socket.read_line(&mut line).await.unwrap() > 0);
                header_bytes += line.len();
                assert!(header_bytes < 16 * 1024);
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
            }
            assert!(length < 16 * 1024);
            socket.read_exact(&mut vec![0; length]).await.unwrap();
            let (status, body) = if first.starts_with("POST /v1/auth/challenge ") {
                ("200 OK", challenge.as_str())
            } else if first.starts_with("POST /v1/auth/verify ") {
                ("200 OK", authenticated.as_str())
            } else if first.starts_with("GET /v1/approvals?state=waiting ") {
                ("200 OK", waiting.as_str())
            } else if first.starts_with("POST /v1/messages/ack ") {
                ("200 OK", "{\"ok\":true}")
            } else {
                assert!(first.starts_with("GET /v1/presence "));
                ("503 Service Unavailable", "{}")
            };
            socket
                .write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes(),
                )
                .await
                .unwrap();
            requests.push(first);
        }
        requests
    });
    let relay = Relay::new(f.core.clone()).unwrap();
    assert!(f.core.snapshot().unwrap().pending.is_empty());
    let (plans, retry) = relay.sync_background_status().await.unwrap();
    assert!(
        retry,
        "the native worker still retries missing control updates"
    );
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].approval_id, request.approval_id);
    assert!(plans[0].quick_allowed);
    assert_eq!(f.core.snapshot().unwrap().pending.len(), 1);
    let requests = server.await.unwrap();
    assert!(requests[2].starts_with("GET /v1/approvals?state=waiting "));
    assert!(requests[4].starts_with("GET /v1/presence "));
}

#[tokio::test]
async fn old_upload_response_cannot_mark_a_new_login_as_uploaded() {
    use std::io::{BufRead, BufReader, Read, Write};
    let f = Fixture::new();
    let issuer = accounts::issuer();
    let (base, server) = accounts::server(&issuer);
    f.core
        .store
        .transaction(|db| Store::delete(db, "peers", &f.peer.device_id))
        .unwrap();
    f.core.set_relay(base.as_str()).unwrap();
    f.core.require_account_login();
    let relay = Relay::new(f.core.clone()).unwrap();
    let sign_in = async |relay: &Relay| {
        let attempt = relay.account_begin("google").await.unwrap();
        relay
            .account_finish(
                &attempt.attempt_id,
                &accounts::token(&issuer, "google", "upload-race-owner", "", now()),
                "",
                "",
            )
            .await
            .unwrap();
    };
    sign_in(&relay).await;
    relay.authenticate().await.unwrap();
    let push = json!({"platform":"apns","token":"b".repeat(64)});
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("http://{}/", listener.local_addr().unwrap());
    let upstream = base.socket_addrs(|| None).unwrap()[0];
    let accepted = Arc::new(tokio::sync::Notify::new());
    let ready = accepted.clone();
    let (release, held) = std::sync::mpsc::channel();
    let proxy_task = std::thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut headers = String::new();
        let mut length = 0;
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse::<usize>().unwrap();
                }
                if name.eq_ignore_ascii_case("connection") {
                    continue;
                }
            }
            headers.push_str(&line);
            assert!(headers.len() < 16 * 1024);
        }
        assert!(headers.starts_with("POST /v1/devices/push-token "));
        assert!((1..16 * 1024).contains(&length));
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let mut remote = std::net::TcpStream::connect(upstream).unwrap();
        remote
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        remote.write_all(headers.as_bytes()).unwrap();
        remote.write_all(b"Connection: close\r\n\r\n").unwrap();
        remote.write_all(&body).unwrap();
        let mut response = Vec::new();
        remote.read_to_end(&mut response).unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 "));
        ready.notify_one();
        held.recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        client.write_all(&response).unwrap();
    });
    // The old session's upload is accepted by the real relay, but its response is held.
    f.core
        .store
        .transaction(|db| {
            let mut settings: SettingsView = f.core.store.get(db, "meta", "settings")?.unwrap();
            settings.relay_url = proxy.clone();
            f.core.store.put(db, "meta", "settings", &settings, 0)?;
            let mut session: crate::account::Session =
                f.core.store.get(db, "meta", "account_session")?.unwrap();
            session.relay_url = proxy.clone();
            f.core
                .store
                .put(db, "meta", "account_session", &session, 0)?;
            f.core.store.put(db, "meta", "push_token", &push, 0)
        })
        .unwrap();
    let uploading = relay.clone();
    let upload = tokio::spawn(async move { uploading.sync_push_token().await });
    tokio::time::timeout(std::time::Duration::from_secs(5), accepted.notified())
        .await
        .unwrap();
    // Restore the real URL for logout and re-login, preserving the same provider token.
    f.core
        .store
        .transaction(|db| {
            let mut settings: SettingsView = f.core.store.get(db, "meta", "settings")?.unwrap();
            settings.relay_url = base.as_str().into();
            f.core.store.put(db, "meta", "settings", &settings, 0)?;
            let mut session: crate::account::Session =
                f.core.store.get(db, "meta", "account_session")?.unwrap();
            session.relay_url = base.as_str().into();
            f.core.store.put(db, "meta", "account_session", &session, 0)
        })
        .unwrap();
    relay.account_logout().await.unwrap();
    f.core
        .store
        .transaction(|db| Store::delete(db, "meta", "push_token"))
        .unwrap();
    let current = Relay::new(f.core.clone()).unwrap();
    sign_in(&current).await;
    f.core
        .store
        .transaction(|db| f.core.store.put(db, "meta", "push_token", &push, 0))
        .unwrap();
    release.send(()).unwrap();
    upload.await.unwrap().unwrap();
    proxy_task.join().unwrap();
    assert!(f
        .core
        .store
        .transaction(|db| f
            .core
            .store
            .get::<String>(db, "meta", "uploaded_push_token"))
        .unwrap()
        .is_none());
    current.sync_push_token().await.unwrap();
    server.inspect(|db| {
        let bytes: Vec<u8> = db
            .query_row(
                "SELECT push_token FROM devices WHERE id=?1",
                [&f.core.device().device_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), push);
    });
    server.shutdown().await;
}
