use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use crate::app_state::AppState;
use crate::domain::{AuthAPIError, BannedTokenStore, EmailClient, TwoFACodeStore, UserStore};
use crate::utils::auth::validate_token;

pub async fn logout<T, U, V, W>(
    State(state): State<AppState<T, U, V, W>>,
    jar: CookieJar) -> Result<(CookieJar, impl IntoResponse), AuthAPIError>
where T: UserStore,
      U: BannedTokenStore,
      V: TwoFACodeStore,
      W: EmailClient
{
    let jar_binding = jar.to_owned();
    // get the jwt cookie from the cookie jar
    let cookie = match jar_binding.get("jwt") {
        Some(cookie) => {
            // validate the jwt token
            match validate_token(cookie.value()).await {
                Ok(_) => cookie,
                // if the token is invalid, return an error
                Err(_) => return Err(AuthAPIError::InvalidToken),
            }
        },
        // if the jwt cookie is missing, return an error
        None =>  return Err(AuthAPIError::MissingToken),
    };

    // add the token to the banned token store
    let mut banned_token_store = state.banned_token_store.write().await;
    let token = cookie.value();
    banned_token_store.add_banned_token(token.to_string()).await
        .map_err(|_| AuthAPIError::UnexpectedError)?;

    // remove the jwt cookie from the cookie jar
    let jar = jar.remove(cookie.to_string());

    Ok((jar, StatusCode::OK.into_response()))
}
