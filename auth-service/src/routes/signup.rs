use axum::{
    Json,
    response::IntoResponse,
    extract::State,
};
use serde::{Deserialize};

use crate::{
    app_state::AppState,
    domain::{
        User,
        AuthAPIError
    },
    http_response::{
        AuthMessage
    },
};

fn is_valid_email(email: &str) -> bool {
    match email {
        email if email.is_empty() => false,
        email if !email.contains('@') => false,
        _ => true,
    }
}

fn is_valid_password(password: &str) -> bool {
    match password {
        password if password.is_empty() => false,
        password if password.len() < 8 => false,
        _ => true,
    }
}

#[derive(Deserialize, Debug)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = request.email;
    let password = request.password;

    if !is_valid_email(&email) || !is_valid_password(&password) {
        return Err(AuthAPIError::InvalidCredentials);
    }

    // Create a new `User` instance using data in the `request`
    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    if user_store.get_user(&user.email).is_ok() {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    match user_store.add_user(user) {
        Ok(_) => {
            Ok(AuthMessage::UserCreated.into_response())
        },
        Err(_) => Err(AuthAPIError::UnexpectedError),
    }
}