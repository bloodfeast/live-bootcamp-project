use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use auth_service::app_state::AppState;
use auth_service::Application;
use auth_service::services::HashmapUserStore;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

pub fn get_malformed_email() -> String {
    "example.com".to_owned()
}

impl TestApp {
    pub async fn new() -> Self {
        let user_store = HashmapUserStore::default();
        let app_state = AppState::new(Arc::new(RwLock::new(user_store)));

        let app = Application::build(app_state, "127.0.0.1:0")
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address().to_string());

        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(async { app.run().await });
        let http_client = reqwest::Client::builder().build().expect("Failed to build HTTP client");


        Self {
            address,
            http_client,
        }
    }

    // Route Tests
    //
    // - GET /
    // - POST /signup
    // - POST /login
    // - POST /logout
    // - POST /verify-2fa
    // - POST /verify-token
    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_signup<T>(&self, body: &T) -> reqwest::Response
    where T: serde::Serialize + ?Sized
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_login<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_logout<T>(&self, body: &T) -> reqwest::Response
    where T: serde::Serialize + ?Sized
    {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_verify_2fa<T>(&self, body: &T) -> reqwest::Response
    where T: serde::Serialize + ?Sized
    {
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_verify_token<T>(&self, body: &T) -> reqwest::Response
    where T: serde::Serialize + ?Sized
    {
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .expect("Failed to send request")
    }

}