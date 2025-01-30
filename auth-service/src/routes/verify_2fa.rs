use std::str::FromStr;
use axum::{http::StatusCode, response::IntoResponse, Json};
use axum::extract::State;
use axum_extra::extract::CookieJar;
use crate::app_state::AppState;
use crate::domain::{AuthAPIError, BannedTokenStore, Email, EmailClient, LoginAttemptId, TwoFACode, TwoFACodeStore, UserStore};

#[derive(Debug, serde::Deserialize)]
pub struct Verify2FARequest {
    email: String,
    login_attempt_id: String,
    two_fac_code: String,
}

pub async fn verify_2fa<T, U, V, W>(
    State(state): State<AppState<T, U, V, W>>,
    Json(request): Json<Verify2FARequest>
) -> Result<impl IntoResponse, AuthAPIError>
where T: UserStore + Clone + Send + Sync + 'static,
      U: BannedTokenStore + Clone + Send + Sync + 'static,
      V: TwoFACodeStore + Clone + Send + Sync + 'static,
      W: EmailClient + Clone + Send + Sync + 'static
{
    let email = Email::from_str(request.email.as_str())
        .map_err(|_| AuthAPIError::MalformedRequest)?;

    let login_attempt_id = LoginAttemptId::from_str(request.login_attempt_id.as_str())
        .map_err(|_| AuthAPIError::MalformedRequest)?;


    let two_fac_code = TwoFACode::from_str(request.two_fac_code.as_str())
        .map_err(|_| AuthAPIError::MissingToken)?;

    let mut two_fac_code_store = state.two_fa_code_store.write().await;
    let stored_code_tuple = two_fac_code_store.get_code(&email).await
        .map_err(|_| AuthAPIError::InvalidCredentials);

    return match stored_code_tuple {
        Ok(t) => {
            if t.0 == login_attempt_id && t.1 == two_fac_code {
                // Remove the code from the store, so it can't be used again.
                two_fac_code_store.remove_code(&email).await
                    .map_err(|_| AuthAPIError::UnexpectedError)?;

                Ok(StatusCode::OK)
            } else {
                Err(AuthAPIError::InvalidCredentials)
            }
        },
        Err(_) => Err(AuthAPIError::InvalidCredentials)
    };
}