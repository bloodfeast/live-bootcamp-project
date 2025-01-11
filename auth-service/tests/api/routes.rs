use crate::helpers::TestApp;

#[tokio::test]
async fn root_returns_auth_ui() {
    let app = TestApp::new().await;

    let response = app.get_root().await;

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}

#[tokio::test]
async fn signup_returns_200() {
    let app = TestApp::new().await;

    let response = app.post_signup(r#"{"email": "[email protected]", "password": "password"}"#).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn login_returns_200() {
    let app = TestApp::new().await;

    let response = app.post_login(r#"{"email": "[email protected]", "password": "password"}"#).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn logout_returns_200() {
    let app = TestApp::new().await;

    let response = app.post_logout(r#"{"email": "[email protected]"}"#).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_2fa_returns_200() {
    let app = TestApp::new().await;

    let response = app
        .post_verify_2fa(r#"{"email": "[email protected]", "password": "password", "token": "123456"}"#)
        .await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_token_returns_200() {
    let app = TestApp::new().await;

    let response = app
        .post_verify_token(r#"{"email": "[email protected]", "password": "password", "token": "123456"}"#)
        .await;

    assert_eq!(response.status().as_u16(), 200);
}

