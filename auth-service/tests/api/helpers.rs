use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

impl TestApp {
    pub async fn new() -> Self {
        let app = auth_service::Application::build("127.0.0.1:0")
            .await
            .expect("Failed to build application");
        let address = format!("http://{}", app.address.clone());

        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());
        let http_client = reqwest::Client::new();

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

    pub async fn post_login<T>(&self, body: &T) -> reqwest::Response
    where T: serde::Serialize + ?Sized
    {
        self.http_client
            .post(&format!("{}/login", &self.address))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .expect("Failed to send request")
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