use std::str::FromStr;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::CookieJar;
use crate::app_state::AppState;
use crate::domain::{AuthAPIError, BannedTokenStore, Email, UserStore};
use crate::utils::auth::generate_auth_cookie;
use crate::utils::constants::JWT_COOKIE_NAME;

#[derive(Debug, serde::Deserialize)]
pub struct RefreshTokenRequest {
    pub email: String,
    pub token: String,
}

pub async fn refresh_token<T, U>(
    State(state): State<AppState<T, U>>,
    jar: CookieJar,
    Json(request): Json<RefreshTokenRequest>,
) -> (CookieJar, Result<StatusCode, AuthAPIError>)
where T: UserStore + Clone + Send + Sync + 'static,
      U: BannedTokenStore + Clone + Send + Sync + 'static,
{
    let email = match Email::from_str(request.email.as_str()) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials))
    };

    match state.user_store.read().await.get_user(&email).await {
        Ok(_) => (),
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials))
    };

    let token = request.token;

    let prev_cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie.clone(),
        None => return (jar, Err(AuthAPIError::InvalidToken))
    };

    let updated_jar = jar.remove(prev_cookie);

    let mut banned_token_store = state.banned_token_store.write().await;
    match banned_token_store.add_banned_token(token.clone()).await {
        Ok(_) => {},
        Err(_) => {
            return (updated_jar, Err(AuthAPIError::InvalidToken));
        },
    };

    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(_) => return (updated_jar, Err(AuthAPIError::UnexpectedError))
    };

    let updated_jar = updated_jar.add(auth_cookie);

    (updated_jar, Ok(StatusCode::OK))
}