use std::str::FromStr;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use crate::app_state::AppState;
use crate::domain::{
    AuthAPIError,
    BannedTokenStore,
    Email,
    EmailClient,
    LoginAttemptId,
    Password,
    TwoFACode,
    TwoFACodeStore,
    UserStore
};
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

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

pub async fn login<T, U, V, W>(
    State(state): State<AppState<T, U, V, W>>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthAPIError>
where T: UserStore,
      U: BannedTokenStore,
      V: TwoFACodeStore,
      W: EmailClient
{
    let email = Email::from_str(request.email.as_str())
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    let user_store = state.user_store.write().await;
    user_store.validate_user(&email, &Password::from_str(&request.password)?).await
        .map_err(|_| {
            eprintln!("User validation failed");
            AuthAPIError::InvalidCredentials
        })?;

    let user = user_store.get_user(&email).await
        .map_err(|_| AuthAPIError::InvalidCredentials)?;

    match user.requires_2fa {
        true => handle_2fa(&email, &state, jar).await,
        false => handle_no_2fa(&email, jar).await,
    }
}

async fn handle_2fa<T, U, V, W>(
    email: &Email,
    state: &AppState<T, U, V, W>,
    jar: CookieJar,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), AuthAPIError>
where T: UserStore + Clone + Send + Sync + 'static,
      U: BannedTokenStore + Clone + Send + Sync + 'static,
      V: TwoFACodeStore + Clone + Send + Sync + 'static,
      W: EmailClient + Clone + Send + Sync + 'static,
{

    let login_attempt_id = LoginAttemptId::default();
    let two_fa_code = TwoFACode::default();

    let mut two_fa_code_store = state.two_fa_code_store.write().await;
    two_fa_code_store
        .add_code(email, login_attempt_id.clone(), two_fa_code.clone())
        .await
        .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;

    state.email_client.write().await
        .send_email(email, "2 factor auth code", two_fa_code.to_string().as_str()).await
        .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;

    let response = TwoFactorAuthResponse {
        message: "2FA required".to_string(),
        login_attempt_id: login_attempt_id.as_ref().to_string(),
    };
    let auth_cookie = generate_auth_cookie(&email)
        .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;

    let updated_jar = jar.add(auth_cookie);

    let json_response = Json(LoginResponse::TwoFactorAuth(response));

    Ok((updated_jar, (StatusCode::PARTIAL_CONTENT, json_response)))
}

async fn handle_no_2fa(
    email: &Email,
    jar: CookieJar,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), AuthAPIError>
{
    let auth_cookie = generate_auth_cookie(&email)
        .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;
    let updated_jar = jar.add(auth_cookie);

    let status = StatusCode::OK;
    let json_response = Json(LoginResponse::RegularAuth);

    Ok((updated_jar, (status, json_response)))
}