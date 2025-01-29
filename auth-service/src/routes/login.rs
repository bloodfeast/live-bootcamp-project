use std::str::FromStr;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use crate::app_state::AppState;
use crate::domain::{AuthAPIError, BannedTokenStore, Email, LoginAttemptId, Password, TwoFACode, TwoFACodeStore, UserStore};
use crate::utils::auth::generate_auth_cookie;

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

// If a user requires 2FA, this JSON body should be returned!
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

pub async fn login<T, U, V>(
    State(state): State<AppState<T, U, V>>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError>
where T: UserStore + Clone + Send + Sync + 'static,
      U: BannedTokenStore + Clone + Send + Sync + 'static,
      V: TwoFACodeStore + Clone + Send + Sync + 'static,
{
    let email = Email::from_str(request.email.as_str())
        .map_err(|_| AuthAPIError::InvalidCredentials)?;
    let password = Password::from_str(&request.password.as_str())
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = state.user_store.read().await;
    let user = user_store.get_user(&email).await
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    match user.password == password {
        true => {},
        false => return Err(AuthAPIError::InvalidCredentials),
    };

    let auth_cookie = generate_auth_cookie(&email)
        .map_err(|_| AuthAPIError::UnexpectedError)?;
    let updated_jar = jar.add(auth_cookie);

    match user.requires_2fa {
        true => handle_2fa(&email, &state, updated_jar).await
            .map(|(jar, status, json_response)|
                Ok((jar, (status, json_response)))
            )?,
        false => handle_no_2fa(&user.email, updated_jar).await
            .map(|(jar, status, json_response)|
                Ok((jar, (status, json_response)))
            )?,
    }
}

async fn handle_2fa<T, U, V>(
    email: &Email,
    state: &AppState<T, U, V>,
    jar: CookieJar,
) -> Result<(
    CookieJar,
    StatusCode,
    Json<LoginResponse>),
    AuthAPIError>
where T: UserStore + Clone + Send + Sync + 'static,
      U: BannedTokenStore + Clone + Send + Sync + 'static,
      V: TwoFACodeStore + Clone + Send + Sync + 'static,
{
    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    let mut two_fa_code_store = state.two_fa_code_store.write().await;
    two_fa_code_store.add_code(email, login_attempt_id.clone(), two_fa_code.clone())
        .await
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    let response = TwoFactorAuthResponse {
        message: "2FA required".to_string(),
        login_attempt_id: login_attempt_id.as_ref().to_string(),
    };

    Ok((
        jar,
        StatusCode::PARTIAL_CONTENT,
        Json(LoginResponse::TwoFactorAuth(response))
    ))
}

// New!
async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> Result<
    (
        CookieJar,
        StatusCode,
        Json<LoginResponse>
    ),
    AuthAPIError
> {
    let auth_cookie = generate_auth_cookie(email)
        .map_err(|_| AuthAPIError::UnexpectedError)?;
    let updated_jar = jar.add(auth_cookie);
    let status = StatusCode::OK;
    let json_response = Json(LoginResponse::RegularAuth);

    Ok((updated_jar, status, json_response))
}