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
        "requires2FA": true
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let response = app.post_login(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": true
    })).await;
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn login_returns_422_on_malformed_credentials() {

    let app = TestApp::new().await;
    let email = &get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": true
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let test_cases = [
        serde_json::json!({
            "email": email,
        }),
        serde_json::json!({
            "email": email,
            "requires2FA": true
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
async fn login_returns_401_on_invalid_credentials() {
    let app = TestApp::new().await;
    let email = &get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": true
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
            401,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn login_returns_401_on_non_existent_user() {
    let app = TestApp::new().await;
    let email = &get_random_email();
    let response = app.post_signup(&serde_json::json!({
        "email": email,
        "password": "password",
        "requires2FA": true
    })).await;
    assert_eq!(response.status().as_u16(), 201);

    let response = app.post_login(&serde_json::json!({
        "email": get_random_email(),
        "password": "password",
    })).await;
    assert_eq!(response.status().as_u16(), 401);
}