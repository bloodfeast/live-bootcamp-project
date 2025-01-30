use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use crate::app_state::AppState;
use crate::domain::{AuthAPIError, BannedTokenStore, EmailClient, TwoFACodeStore, UserStore};

#[derive(Debug, serde::Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

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

    let banned_token_store = state.banned_token_store.read().await;
    match banned_token_store.is_banned(&token).await {
        result => {
            let is_banned = result
                .map_err(|_| AuthAPIError::UnexpectedError)?;
            if is_banned {
                return Err(AuthAPIError::InvalidToken);
            }
            Ok(StatusCode::OK)
        },
    }
}

