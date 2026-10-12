use super::*;
use crate::tests::fixture;
use tokio::net::TcpListener;

#[tokio::test]
async fn middleware_normalizes_extractor_errors_and_preserves_json_errors() {
    let fixture = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
        .route(
            "/v1/devices",
            get(|| async { StatusCode::PAYLOAD_TOO_LARGE }),
        )
        .route(
            "/v1/auth/challenge",
            get(|| async { StatusCode::NOT_FOUND }),
        )
        .route("/v1/health", get(|| async { StatusCode::BAD_REQUEST }))
        .layer(middleware::from_fn_with_state(fixture.state, guard));
    let (shutdown, done) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = done.await;
            })
            .await
            .unwrap();
    });
    for (path, status, code) in [
        (
            "/v1/devices",
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
        ),
        ("/v1/auth/challenge", StatusCode::NOT_FOUND, "not_found"),
        ("/v1/health", StatusCode::BAD_REQUEST, "bad_envelope"),
    ] {
        let response = reqwest::get(format!("http://{address}{path}"))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            code
        );
    }
    shutdown.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn metrics_query_failure_returns_a_static_storage_error() {
    let fixture = fixture();
    fixture
        .state
        .with(|data, _| {
            data.db.execute_batch("DROP TABLE approvals")?;
            Ok(())
        })
        .unwrap();
    let response = metrics(State(fixture.state)).await.unwrap_err();
    assert_eq!(response.code, kv_core::remote::relay::ErrorCode::Conflict);
}
