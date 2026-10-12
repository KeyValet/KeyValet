use crate::auth;
use crate::error::{ApiError, Result};
use crate::messages;
use crate::pairing;
use crate::presence;
use crate::state::State as RelayState;
use axum::body::to_bytes;
use axum::extract::{FromRequest, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use kv_core::remote::canonical::from_json;
use kv_core::remote::relay::HealthResponse;
use kv_core::remote::Extra;
use serde::de::DeserializeOwned;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub(crate) const MAX_BODY: usize = 1024 * 1024;

pub(crate) struct Wire<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Wire<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, _: &S) -> Result<Self> {
        let is_json = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| {
                h.split(';')
                    .next()
                    .is_some_and(|v| v.trim() == "application/json")
            });
        if !is_json {
            return Err(ApiError::bad());
        }
        let bytes = to_bytes(request.into_body(), MAX_BODY)
            .await
            .map_err(|_| ApiError::too_large())?;
        Ok(Self(from_json(&bytes)?))
    }
}

#[cfg(test)]
#[path = "unit_tests/http.rs"]
mod tests;

pub(crate) fn router(state: Arc<RelayState>) -> Router {
    Router::new()
        .route("/v1/devices", post(auth::register))
        .route(
            "/v1/devices/push-token",
            post(crate::account::push_token).delete(crate::account::remove_push_token),
        )
        .route("/v1/devices/{id}", axum::routing::delete(auth::revoke))
        .route("/v1/auth/challenge", post(auth::challenge))
        .route("/v1/auth/verify", post(auth::verify))
        .route("/v1/recovery", post(auth::recover))
        .route("/v1/account/providers", get(crate::account::providers))
        .route("/v1/account/begin", post(crate::account::begin))
        .route("/v1/account/finish", post(crate::account::finish))
        .route("/v1/account/session", get(crate::account::session))
        .route("/v1/account/logout", post(crate::account::logout))
        .route(
            "/v1/account/apple/callback",
            post(crate::account::apple_callback),
        )
        .route("/v1/presence", get(presence::upgrade))
        .route("/v1/pair/start", post(pairing::start))
        .route("/v1/pair/complete", post(pairing::complete))
        .route("/v1/pair/finish", post(pairing::finish))
        .route(
            "/v1/approvals",
            post(messages::submit).get(messages::waiting),
        )
        .route("/v1/approvals/{id}/reply", post(messages::reply))
        .route("/v1/approvals/{id}/cancel", post(messages::cancel))
        .route("/v1/messages", post(messages::messages))
        .route("/v1/messages/ack", post(messages::ack))
        .route("/v1/health", get(health))
        .route("/metrics", get(metrics))
        .fallback(|| async { ApiError::not_found() })
        .method_not_allowed_fallback(|| async { ApiError::bad() })
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

async fn guard(State(state): State<Arc<RelayState>>, request: Request, next: Next) -> Response {
    state.requests.fetch_add(1, Ordering::Relaxed);
    let path = request.uri().path().to_owned();
    let public = matches!(
        path.as_str(),
        "/v1/devices"
            | "/v1/auth/challenge"
            | "/v1/auth/verify"
            | "/v1/recovery"
            | "/v1/pair/complete"
            | "/v1/health"
            | "/v1/account/providers"
            | "/v1/account/begin"
            | "/v1/account/finish"
            | "/v1/account/session"
            | "/v1/account/logout"
            | "/v1/account/apple/callback"
    );
    if !public {
        if let Err(error) =
            state.with(|data, now| data.authenticate(request.headers(), now).map(|_| ()))
        {
            return error.into_response();
        }
    }
    let response = next.run(request).await;
    let mut response = if response.status().is_client_error()
        && response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_none_or(|h| h != "application/json")
    {
        match response.status() {
            StatusCode::PAYLOAD_TOO_LARGE => ApiError::too_large(),
            StatusCode::NOT_FOUND => ApiError::not_found(),
            _ => ApiError::bad(),
        }
        .into_response()
    } else {
        response
    };
    if path.starts_with("/v1/account/") || path == "/v1/recovery" {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    }
    // Never log URI, headers, request bodies, signatures, tokens or error text.
    state.event("http_response", response.status().as_u16() as usize);
    response
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        version: env!("CARGO_PKG_VERSION").into(),
        extra: Extra::new(),
    })
}

async fn metrics(State(state): State<Arc<RelayState>>) -> Result<Response> {
    let (online, waiting) = state.with(|data, now| {
        let waiting: i64 = data.db.query_row(
            "SELECT COUNT(*) FROM approvals WHERE state='waiting' AND exp>=?1",
            [now],
            |row| row.get(0),
        )?;
        Ok((data.presence.len(), waiting))
    })?;
    let body = format!(
        "# TYPE kv_relay_requests_total counter\nkv_relay_requests_total {}\n\
        # TYPE kv_relay_online_devices gauge\nkv_relay_online_devices {online}\n\
        # TYPE kv_relay_waiting_approvals gauge\nkv_relay_waiting_approvals {waiting}\n",
        state.requests.load(Ordering::Relaxed)
    );
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
        .into_response())
}
