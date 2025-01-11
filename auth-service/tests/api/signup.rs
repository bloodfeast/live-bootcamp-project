use crate::helpers::{get_random_email, TestApp};
#[tokio::test]
async fn should_return_200_for_happy_path() {
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
            "email": "some_email@some_domain.com",
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": "some.email@some.domain.com",
            "password": "password123",
            "requires2FA": true
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            200,
            "Failed for input: {:?}",
            test_case
        );
    }
}
#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email(); // Call helper method to generate email

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}