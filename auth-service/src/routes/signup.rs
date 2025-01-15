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

    if email.is_empty() || !email.contains('@') {
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