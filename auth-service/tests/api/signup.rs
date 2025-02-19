use auth_service::http_response::{AuthMessageResponse, ErrorResponse};
use crate::helpers::{
    get_random_email,
    get_malformed_email,
    TestApp,
};

#[test_helpers::api_test]
async fn should_return_201_if_valid_input() {

    let random_email = get_random_email(); // Call helper method to generate email

    let response = app
        .post_signup(&serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": true
        }))
        .await;

    assert_eq!(response.status().as_u16(), 201);

    let expected_response = AuthMessageResponse {
        message_body: "User created successfully!".to_owned(),
    };

    // Assert that we are getting the correct response body!
    assert_eq!(
        response
            .json::<AuthMessageResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );
    
}

#[test_helpers::api_test]
async fn should_return_422_if_malformed_input() {

    let random_email = get_random_email(); // Call helper method to generate email

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": false
        }),
        serde_json::json!({
            "email": random_email,
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123"
        }),
        serde_json::json!({
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

#[test_helpers::api_test]
async fn should_return_401_if_invalid_input() {

    let test_cases = [
        serde_json::json!({
            "email": "",
            "password": "password",
            "requires2FA": false
        }),
        serde_json::json!({
            "email": get_malformed_email(),
            "password": "password",
            "requires2FA": false
        }),
        serde_json::json!({
            "email": get_random_email(),
            "password": "pass",
            "requires2FA": false
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;

        assert_eq!(response.status().as_u16(), 401, "Failed for input: {:?}", test_case);

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }
    

}

#[test_helpers::api_test]
async fn should_return_409_if_email_already_exists() {

    let random_email = get_random_email(); // Call helper method to generate email

    let response = app
        .post_signup(&serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": false
        }))
        .await;

    assert_eq!(response.status().as_u16(), 201);

    let response = app
        .post_signup(&serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": false
        }))
        .await;

    assert_eq!(response.status().as_u16(), 409);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );
    
}
