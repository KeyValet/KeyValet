use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kv_core::remote::relay::{Error, ErrorCode, ErrorResponse};
use kv_core::remote::{Extra, RemoteError};

pub(crate) type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
pub(crate) struct ApiError {
    pub code: ErrorCode,
    pub message: &'static str,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    pub fn bad() -> Self {
        Self::new(ErrorCode::BadEnvelope, "Invalid request or envelope.")
    }

    pub fn unauthorized() -> Self {
        Self::new(
            ErrorCode::Unauthorized,
            "A valid device session is required.",
        )
    }

    pub fn forbidden() -> Self {
        Self::new(
            ErrorCode::Forbidden,
            "The device is not authorized for this operation.",
        )
    }

    pub fn conflict() -> Self {
        Self::new(
            ErrorCode::Conflict,
            "The operation has already been consumed or conflicts with state.",
        )
    }

    pub fn expired() -> Self {
        Self::new(ErrorCode::Expired, "The operation has expired.")
    }

    pub fn not_found() -> Self {
        Self::new(
            ErrorCode::NotFound,
            "The requested resource does not exist.",
        )
    }

    pub fn rate_limited() -> Self {
        Self::new(
            ErrorCode::RateLimited,
            "The relay capacity or rate limit was reached.",
        )
    }

    pub fn too_large() -> Self {
        Self::new(
            ErrorCode::PayloadTooLarge,
            "The request or envelope is too large.",
        )
    }

    pub fn body(&self) -> ErrorResponse {
        ErrorResponse {
            error: Error {
                code: self.code,
                message: self.message.into(),
                extra: Extra::new(),
            },
            extra: Extra::new(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.code {
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::BadEnvelope => StatusCode::BAD_REQUEST,
            ErrorCode::Expired => StatusCode::GONE,
            ErrorCode::Conflict => StatusCode::CONFLICT,
        };
        let mut response = (status, Json(self.body())).into_response();
        if matches!(self.code, ErrorCode::RateLimited) {
            response
                .headers_mut()
                .insert("retry-after", "60".parse().unwrap());
        }
        response
    }
}

impl From<RemoteError> for ApiError {
    fn from(error: RemoteError) -> Self {
        match error {
            RemoteError::PayloadTooLarge => Self::too_large(),
            RemoteError::Expired => Self::expired(),
            RemoteError::Replay | RemoteError::NotWaiting => Self::conflict(),
            _ => Self::bad(),
        }
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(_: rusqlite::Error) -> Self {
        // Database errors can contain user-supplied data; never print their text.
        Self::new(
            ErrorCode::Conflict,
            "Relay storage is unavailable or conflicts with existing data.",
        )
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(_: serde_json::Error) -> Self {
        Self::bad()
    }
}

impl From<argon2::password_hash::Error> for ApiError {
    fn from(_: argon2::password_hash::Error) -> Self {
        Self::conflict()
    }
}

impl From<tokio::task::JoinError> for ApiError {
    fn from(_: tokio::task::JoinError) -> Self {
        Self::conflict()
    }
}
