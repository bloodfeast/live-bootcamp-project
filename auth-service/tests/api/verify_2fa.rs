use crate::helpers::{get_random_email, TestApp};
use auth_service::domain::{LoginAttemptId, TwoFACode};
use auth_service::http_response::ErrorResponse;

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
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login request. This should fail.
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
#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let login_attempt_id = LoginAttemptId::default().as_ref().to_owned();
    let two_fa_code = TwoFACode::default().as_ref().to_owned();

    let test_cases = vec![
        (
            "invalid_email",
            login_attempt_id.as_str(),
            two_fa_code.as_str(),
        ),
        (
            random_email.as_str(),
            "invalid_login_attempt_id",
            two_fa_code.as_str(),
        ),
        (
            random_email.as_str(),
            login_attempt_id.as_str(),
            "invalid_two_fa_code",
        ),
        ("", "", ""),
    ];

    for (email, login_attempt_id, code) in test_cases {
        let request_body = serde_json::json!({
            "email": email,
            "loginAttemptId": login_attempt_id,
            "2FACode": code
        });

        let response = app.post_verify_2fa(&request_body).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            request_body
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Malformed request".to_owned()
        );
    }
}