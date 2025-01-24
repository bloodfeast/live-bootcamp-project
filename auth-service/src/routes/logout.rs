use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum_extra::extract::CookieJar;
use crate::domain::AuthAPIError;
use crate::utils::auth::validate_token;

pub async fn logout(jar: CookieJar) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {

    let jar_binding = jar.to_owned();
    let cookie = match jar_binding.get("jwt") {
        Some(cookie) => cookie,
        None =>  return (jar, Err(AuthAPIError::MissingToken)),
    };

    let valid_cookie = validate_token(cookie.value()).await;

    if let Err(_) = valid_cookie {
        return (jar, Err(AuthAPIError::InvalidToken));
    };

    let jar = jar.remove(cookie.to_string());

    (jar, Ok(StatusCode::OK.into_response()))

}
