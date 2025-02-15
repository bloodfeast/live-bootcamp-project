use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use crate::app_state::AppState;
use crate::domain::{AuthAPIError, BannedTokenStore, EmailClient, TwoFACodeStore, UserStore};
use crate::utils;

#[derive(Debug, serde::Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

#[tracing::instrument(name = "Verify Token", skip_all)]
pub async fn verify_token<T, U, V, W>(
    State(state): State<AppState<T, U, V, W>>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<StatusCode, AuthAPIError>
where T: UserStore,
      U: BannedTokenStore,
      V: TwoFACodeStore,
      W: EmailClient
{
    let token = request.token;

    match utils::auth::validate_token(&token, state.banned_token_store.clone().read().await).await {
        Ok(_) =>  Ok(StatusCode::OK),
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}

