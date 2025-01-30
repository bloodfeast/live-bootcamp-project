use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn refresh_token_returns_200() {
    let app = TestApp::new().await;
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

    let token = login_response.headers().get("set-cookie")
        .unwrap().to_str()
        .unwrap().split_once('=')
        .unwrap().1.split_once(';')
        .unwrap().0;

    let response = app.post_refresh_token(&serde_json::json!({
        "email": email,
        "password": "password",
        "token": token
    })).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn refresh_token_returns_401_on_invalid_token() {
    let app = TestApp::new().await;
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

    let token = login_response.headers().get("set-cookie")
        .unwrap().to_str()
        .unwrap().split_once('=')
        .unwrap().1.split_once(';')
        .unwrap().0;

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

#[tokio::test]
async fn refresh_token_returns_401_on_invalid_email() {
    let app = TestApp::new().await;
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

    let token = login_response.headers().get("set-cookie")
        .unwrap().to_str()
        .unwrap().split_once('=')
        .unwrap().1.split_once(';')
        .unwrap().0;

    let response = app.post_refresh_token(&serde_json::json!({
        "email": get_random_email(),
        "password": "password",
        "token": token
    })).await;

    assert_eq!(response.status().as_u16(), 401);
}

