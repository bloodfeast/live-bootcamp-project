use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_200_if_token_is_not_banned() {
    let app = TestApp::new().await;

    let email = &get_random_email();
    let _ = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": true
    })).await;

    let login_response = app.post_login(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": true
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
}


#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let response = app
        .post_verify_token(r#"{"email": "example.com", "password": "password", "token": " "}"#)
        .await;

    assert_eq!(response.status().as_u16(), 422);
}