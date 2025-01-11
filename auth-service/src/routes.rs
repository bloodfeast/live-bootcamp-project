use axum::http::StatusCode;
use axum::response::IntoResponse;

pub async fn signup() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

pub async fn login() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

pub async fn logout() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

//noinspection ALL
pub async fn verify_2fa() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

pub async fn verify_token() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
