use crate::helpers::TestApp;

#[tokio::test]
async fn login_returns_200() {
    let app = TestApp::new().await;

    let response = app.post_login(r#"{"email": "[email protected]", "password": "password"}"#).await;

    assert_eq!(response.status().as_u16(), 200);
}

