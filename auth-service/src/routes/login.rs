use std::str::FromStr;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use crate::app_state::AppState;
use crate::domain::{AuthAPIError, Email, Password, UserStore};

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn login<T>(
    State(state): State<AppState<T>>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>)
where T: UserStore + Clone + Send + Sync + 'static
{
    let email = match Email::from_str(request.email.as_str()) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials))
    };
    let password = match Password::from_str(&request.password.as_str()) {
        Ok(password) => password,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials))
    };

    let user_store = state.user_store.read().await;
    let user = user_store.get_user(&email).await;

    let status = match user {
        Ok(user) => {
            if user.password == password {
                StatusCode::OK.into_response()
            } else {
                StatusCode::UNAUTHORIZED.into_response()
            }
        },
        Err(_) => StatusCode::UNAUTHORIZED.into_response()
    };

    let auth_cookie = match crate::utils::generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError))
    };
    let updated_jar = jar.add(auth_cookie);

    (updated_jar, Ok(status))
}