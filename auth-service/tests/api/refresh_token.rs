use auth_service::utils::constants::JWT_COOKIE_NAME;
use test_helpers::api_test;
use crate::helpers::{get_random_email, TestApp};

#[api_test]
async fn refresh_token_returns_200() {
    let email = &get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_response = app.post_login(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;

    assert_eq!(login_response.status().as_u16(), 200);

    let cookie = login_response.cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("No token found");
    let token = cookie.value();

    let response = app.post_refresh_token(&serde_json::json!({
        "email": email,
        "password": "password",
        "token": token
    })).await;

    assert_eq!(response.status().as_u16(), 200);

}

#[api_test]
async fn refresh_token_returns_401_on_invalid_token() {
    let email = &get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_response = app.post_login(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;

    assert_eq!(login_response.status().as_u16(), 200);

    let cookie = login_response.cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("No token found");
    let token = cookie.value();

    app.post_logout(&serde_json::json!({
        "email": email,
    })).await;

    let response = app.post_refresh_token(&serde_json::json!({
        "email": email,
        "password": "password",
        "token": token
    })).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[api_test]
async fn refresh_token_returns_401_on_invalid_email() {
    let email = &get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let login_response = app.post_login(&serde_json::json!({
        "email": email,
        "password": "password"
    })).await;
    let cookie = login_response.cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("No token found");
    let token = cookie.value();

    let response = app.post_refresh_token(&serde_json::json!({
        "email": get_random_email(),
        "password": "password",
        "token": token
    })).await;

    assert_eq!(response.status().as_u16(), 401);
}

