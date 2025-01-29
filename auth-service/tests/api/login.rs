use auth_service::routes::TwoFactorAuthResponse;
use auth_service::utils::constants::JWT_COOKIE_NAME;
use crate::helpers::{
    TestApp,
    get_random_email,
};


#[tokio::test]
async fn login_returns_200() {
    let app = TestApp::new().await;
    let email = &get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let response = app.post_login(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}

#[tokio::test]
async fn login_returns_422_on_malformed_credentials() {

    let app = TestApp::new().await;
    let email = &get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let test_cases = [
        serde_json::json!({
            "email": email,
        }),
        serde_json::json!({
            "email": email,
            "requires2FA": false
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn login_returns_400_on_invalid_credentials() {
    let app = TestApp::new().await;
    let email = &get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let test_cases = [
        serde_json::json!({
            "email": email,
            "password": "wrong_password",
        }),
        serde_json::json!({
            "email": get_random_email(),
            "password": "password",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn login_returns_400_on_non_existent_user() {
    let app = TestApp::new().await;
    let email = &get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": false
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let response = app.post_login(&serde_json::json!({
        "email": get_random_email(),
        "password": "password",
    })).await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {

    let app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_login(&login_body).await;


    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());
}