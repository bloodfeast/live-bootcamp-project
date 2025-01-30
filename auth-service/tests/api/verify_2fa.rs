use crate::helpers::{get_random_email, TestApp};
use auth_service::domain::LoginAttemptId;
use auth_service::routes::{LoginResponse, TwoFactorAuthResponse};

#[tokio::test]
async fn verify_2fa_returns_200() {
    let app = TestApp::new().await;

    let email = get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": true
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let response = app.post_login(&serde_json::json!({
        "email": email,
        "password": "password",
    })).await;

    assert_eq!(response.status().as_u16(), 206);


    let token = response.headers().get("set-cookie")
        .unwrap().to_str()
        .unwrap().split_once('=')
        .unwrap().1.split_once(';')
        .unwrap().0;

    assert_eq!(!token.is_empty(), true);

}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let response = app
        .post_verify_2fa(r#"{"email": "example.com", "password": "password"}"#)
        .await;

    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

    let email = get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": true
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let response = app.post_login(&serde_json::json!({
        "email": email,
        "password": "wrongpassword",
    })).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login requet. This should fail.
    let app = TestApp::new().await;

    let email = get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": true
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let response = app.post_login(&serde_json::json!({
        "email": email,
        "password": "password",
    })).await;

    assert_eq!(response.status().as_u16(), 206);

    let token = response.headers().get("set-cookie")
        .unwrap().to_str()
        .unwrap().split_once('=')
        .unwrap().1.split_once(';')
        .unwrap().0;

    assert_eq!(!token.is_empty(), true);

    let response = app.post_login(&serde_json::json!({
        "email": email,
        "password": "password",
    })).await;

    assert_eq!(response.status().as_u16(), 206);

}
