use std::str::FromStr;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::CookieJar;
use crate::app_state::AppState;
use crate::domain::{AuthAPIError, BannedTokenStore, Email, EmailClient, TwoFACodeStore, UserStore};
use crate::utils::auth::generate_auth_cookie;
use crate::utils::constants::JWT_COOKIE_NAME;

#[derive(Debug, serde::Deserialize)]
pub struct RefreshTokenRequest {
    pub email: String,
    pub token: String,
}

pub async fn refresh_token<T, U, V, W>(
    State(state): State<AppState<T, U, V, W>>,
    jar: CookieJar,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<(CookieJar, StatusCode), AuthAPIError>
where T: UserStore + Clone + Send + Sync + 'static,
      U: BannedTokenStore + Clone + Send + Sync + 'static,
      V: TwoFACodeStore + Clone + Send + Sync + 'static,
      W: EmailClient + Clone + Send + Sync + 'static
{
    let email = Email::from_str(request.email.as_str())
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    state.user_store.read().await
        .get_user(&email).await
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let token = request.token;

    let prev_cookie = jar.get(JWT_COOKIE_NAME)
        .ok_or(AuthAPIError::InvalidToken)?
        .clone();

    let updated_jar = jar.remove(prev_cookie);

    let mut banned_token_store = state.banned_token_store.write().await;
    banned_token_store.add_banned_token(token.clone()).await
        .map_err(|_| AuthAPIError::InvalidToken)?;

    let auth_cookie = generate_auth_cookie(&email)
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    let updated_jar = updated_jar.add(auth_cookie);

    Ok((updated_jar, StatusCode::OK))
}