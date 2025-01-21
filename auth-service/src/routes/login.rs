use std::str::FromStr;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use crate::app_state::AppState;
use crate::domain::{AuthAPIError, Email, Password, UserStore};

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn login<T>(
    State(state): State<AppState<T>>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError>
where T: UserStore + Clone + Send + Sync + 'static
{
    let email = Email::from_str(request.email.as_str())?;
    let password = Password::from_str(&request.password.as_str())?;

    let user_store = state.user_store.read().await;
    let user = user_store.get_user(&email).await;

    match user {
        Ok(user) => {
            if user.password == password {
                Ok(StatusCode::OK.into_response())
            } else {
                Ok(StatusCode::UNAUTHORIZED.into_response())
            }
        },
        Err(_) => Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}