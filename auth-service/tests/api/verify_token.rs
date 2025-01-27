use crate::helpers::{get_random_email, TestApp};

// Reminder todo:
// - verify_token doesn't check if the user exists already, it only checks if the token is banned \
// we would want to return a 401 or 422 if the token doesn't correspond to any user I would think

#[tokio::test]
async fn should_return_200_if_token_is_not_banned() {
    let app = TestApp::new().await;

    let email = &get_random_email();
    let _ = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;

    let login_response = app.post_login(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;

    let token = login_response.headers().get("set-cookie")
        .unwrap().to_str()
        .unwrap().split_once('=')
        .unwrap().1.split_once(';')
        .unwrap().0;

    let response = app.post_verify_token(&serde_json::json!({
        "email": email,
        "password": "password",
        "token": token
    })).await;

    assert_eq!(response.status().as_u16(), 200);

    let response = app.post_logout(&serde_json::json!({
        "email": email,
    })).await;

    assert_eq!(response.status().as_u16(), 200);

    let response = app.post_verify_token(&serde_json::json!({
        "email": email,
        "password": "password",
        "token": token
    })).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;
    let email = &get_random_email();
    let _ = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;

    let login_response = app.post_login(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;

    let token = login_response.headers().get("set-cookie")
        .unwrap().to_str()
        .unwrap().split_once('=')
        .unwrap().1.split_once(';')
        .unwrap().0;

    let _ = app.post_logout(&serde_json::json!({
        "email": email,
    })).await;

    let response = app.post_verify_token(&serde_json::json!({
        "email": email,
        "password": "password",
        "token": token
    })).await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let response = app
        .post_verify_token(r#"{"email": "example.com", "password": "password", "token": " "}"#)
        .await;

    assert_eq!(response.status().as_u16(), 422);
}