use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use crate::app_state::AppState;
use crate::domain::{AuthAPIError, BannedTokenStore, UserStore};
use crate::utils::auth::validate_token;

pub async fn logout<T, U>(
    State(state): State<AppState<T, U>>,
    jar: CookieJar) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>)
where T: UserStore + Clone + Send + Sync + 'static,
      U: BannedTokenStore + Clone + Send + Sync + 'static,
{
    let jar_binding = jar.to_owned();
    // get the jwt cookie from the cookie jar
    let cookie = match jar_binding.get("jwt") {
        Some(cookie) => {
            // validate the jwt token
            match validate_token(cookie.value()).await {
                Ok(_) => cookie,
                // if the token is invalid, return an error
                Err(_) => return (jar, Err(AuthAPIError::InvalidToken)),
            }
        },
        // if the jwt cookie is missing, return an error
        None =>  return (jar, Err(AuthAPIError::MissingToken)),
    };

    // add the token to the banned token store
    let mut banned_token_store = state.banned_token_store.write().await;
    let token = cookie.value();
    match banned_token_store.add_banned_token(token.to_string()).await {
        Ok(_) => {},
        Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
    }

    // remove the jwt cookie from the cookie jar
    let jar = jar.remove(cookie.to_string());

    (jar, Ok(StatusCode::OK.into_response()))
}
