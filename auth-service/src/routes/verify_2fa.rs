use std::str::FromStr;
use axum::{http::StatusCode, response::IntoResponse, Json};
use axum::extract::State;
use secrecy::Secret;
use crate::app_state::AppState;
use crate::domain::{AuthAPIError, BannedTokenStore, Email, EmailClient, LoginAttemptId, TwoFACode, TwoFACodeStore, UserStore};

#[derive(Debug, serde::Deserialize)]
pub struct Verify2FARequest {
    email: Secret<String>,
    #[serde(rename = "loginAttemptId")]
    login_attempt_id: String,
    #[serde(rename = "2FACode")]
    two_fac_code: String,
}

#[tracing::instrument(name = "Verify 2FA", skip_all)]
pub async fn verify_2fa<T, U, V, W>(
    State(state): State<AppState<T, U, V, W>>,
    Json(request): Json<Verify2FARequest>
) -> Result<impl IntoResponse, AuthAPIError>
where T: UserStore,
      U: BannedTokenStore,
      V: TwoFACodeStore,
      W: EmailClient
{
    let email = Email::parse(request.email)
        .map_err(|_| AuthAPIError::MalformedRequest)?;

    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id)
        .map_err(|_| AuthAPIError::MalformedRequest)?;

    let two_fac_code = TwoFACode::parse(request.two_fac_code)
        .map_err(|_| AuthAPIError::MalformedRequest)?;

    let mut two_fac_code_store = state.two_fa_code_store.write().await;
    let stored_code_tuple = two_fac_code_store.get_code(&email).await
        .map_err(|_| AuthAPIError::InvalidCredentials);

    return match stored_code_tuple {
        Ok((logon_attempt, tfa_code)) => {
            if logon_attempt == login_attempt_id && tfa_code == two_fac_code {
                // Remove the code from the store, so it can't be used again.
                two_fac_code_store.remove_code(&email).await
                    .map_err(|e| AuthAPIError::UnexpectedError(e.into()))?;

                Ok(StatusCode::OK)
            } else {
                Err(AuthAPIError::InvalidCredentials)
            }
        },
        Err(_) => Err(AuthAPIError::InvalidCredentials)
    };
}