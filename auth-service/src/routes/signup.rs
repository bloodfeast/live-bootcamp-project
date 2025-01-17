use std::str::FromStr;
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
use crate::domain::{Email, Password, UserStore};

#[derive(Deserialize, Debug)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

pub async fn signup<T>(
    State(state): State<AppState<T>>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError>
where T: UserStore + Clone + Send + Sync + 'static
{
    let email = Email::from_str(request.email.as_str())?;
    let password = Password::from_str(&request.password)?;

    // Create a new `User` instance using data in the `request`
    let user = User::new(email, password, request.requires_2fa)?;

    let mut user_store = state.user_store.write().await;

    if user_store.get_user(&user.email).await.is_ok() {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    match user_store.add_user(user).await {
        Ok(_) => {
            Ok(AuthMessage::UserCreated.into_response())
        },
        Err(_) => Err(AuthAPIError::UnexpectedError),
    }
}