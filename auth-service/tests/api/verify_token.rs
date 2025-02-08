use auth_service::http_response::ErrorResponse;
use auth_service::utils::constants::JWT_COOKIE_NAME;
use crate::helpers::{get_random_email, TestApp};

// Reminder todo:
// - verify_token doesn't check if the user exists already, it only checks if the token is banned \
// we would want to return a 401 or 422 if the token doesn't correspond to any user I would think

#[test_helpers::api_test]
async fn should_return_200_if_token_is_not_banned() {

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

    let cookie = login_response.cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("No token found");
    let token = cookie.value();

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

#[test_helpers::api_test]
async fn should_return_401_if_invalid_token() {

    let test_cases = vec!["", "invalid_token"];

    for test_case in test_cases {
        let verify_token_body = serde_json::json!({
            "token": test_case,
        });
        let response = app.post_verify_token(&verify_token_body).await;
        assert_eq!(response.status().as_u16(), 401);
        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid token".to_owned()
        );
    };
    
}

#[test_helpers::api_test]
async fn should_return_422_if_malformed_input() {

    let response = app
        .post_verify_token(r#"{"email": "example.com", "password": "password", "token": " "}"#)
        .await;

    assert_eq!(response.status().as_u16(), 422);
    
}