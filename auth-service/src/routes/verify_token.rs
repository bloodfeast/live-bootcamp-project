use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use crate::app_state::AppState;
use crate::domain::{AuthAPIError, BannedTokenStore, UserStore};

#[derive(Debug, serde::Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

pub async fn verify_token<T, U>(
    State(state): State<AppState<T, U>>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<StatusCode, AuthAPIError>
where T: UserStore + Clone + Send + Sync + 'static,
      U: BannedTokenStore + Clone + Send + Sync + 'static,
{
    let token = request.token;

    let banned_token_store = state.banned_token_store.read().await;
    let user = banned_token_store.is_banned(&token).await;

    match user {
        Ok(is_banned) => {
            if is_banned {
                return Err(AuthAPIError::InvalidToken);
            }
            return Ok(StatusCode::OK);
        },
        Err(_) => Err(AuthAPIError::InvalidToken),
    }
}
