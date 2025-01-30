use axum::http::StatusCode;
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use crate::domain::AuthAPIError;

pub enum AuthMessage {
    UserCreated,
    UserLoggedIn,
    UserLoggedOut,
    User2FAVerified,
    UserTokenVerified,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AuthMessageResponse {
    pub message_body: String,
}

impl IntoResponse for AuthMessage {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            AuthMessage::UserCreated => (StatusCode::CREATED, "User created successfully!"),
            AuthMessage::UserLoggedIn => (StatusCode::OK, "User logged in successfully!"),
            AuthMessage::UserLoggedOut => (StatusCode::OK, "User logged out successfully!"),
            AuthMessage::User2FAVerified => (StatusCode::OK, "2FA verified successfully!"),
            AuthMessage::UserTokenVerified => (StatusCode::OK, "Token verified successfully!"),
        };
        let body = Json(AuthMessageResponse {
            message_body: body.to_string(),
        });
        (status, body).into_response()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "Missing token"),
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthAPIError::MalformedRequest => (StatusCode::UNPROCESSABLE_ENTITY, "Malformed request"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}