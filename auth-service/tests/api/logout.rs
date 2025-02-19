use reqwest::Url;
use auth_service::utils::constants::JWT_COOKIE_NAME;
use crate::helpers::{get_random_email, TestApp};

#[test_helpers::api_test]
async fn logout_returns_200() {
    let email = &get_random_email();
    let _ = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;

    let _ = app.post_login(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;

    let response = app.post_logout(r#"{"email": "[email protected]"}"#).await;

    assert_eq!(response.status().as_u16(), 200);
    
}

#[test_helpers::api_test]
async fn should_return_400_if_jwt_cookie_missing() {
    let response = app.post_logout(r#"{"email": "[email protected]"}"#).await;

    assert_eq!(response.status().as_u16(), 400);
    
}

#[test_helpers::api_test]
async fn should_return_401_if_invalid_token() {

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout(r#"{"email": "[email protected]"}"#).await;

    assert_eq!(response.status().as_u16(), 401);
    

}