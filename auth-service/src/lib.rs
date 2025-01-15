use std::error::Error;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    serve::Serve,
    Json, Router,
};
use domain::AuthAPIError;
use serde::{Deserialize, Serialize};
use tower_http::services::ServeDir;

pub mod routes;
pub mod domain;
pub mod services;
pub mod app_state;

use app_state::AppState;

// This struct encapsulates our application-related logic.
#[derive(Debug)]
pub struct Application {
    server: Serve<Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    address: String,
}

impl Application {
    pub async fn build(app_state: AppState,address: &str) -> Result<Self, Box<dyn Error>> {
        let router = Router::new()
            .nest_service("/", ServeDir::new("assets"))
            .route("/signup", post(routes::signup))
            .route("/login", post(routes::login))
            .route("/logout", post(routes::logout))
            .route("/verify-2fa", post(routes::verify_2fa))
            .route("/verify-token", post(routes::verify_token))
            .with_state(app_state);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(
            Self {
                server,
                address
            }
        )
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }

    pub fn address(&self) -> &str {
        &self.address
    }
}

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

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
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