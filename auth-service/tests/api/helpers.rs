use std::str::FromStr;
use std::sync::Arc;
use reqwest::cookie::Jar;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::sync::RwLock;
use uuid::Uuid;
use auth_service::app_state::AppState;
use auth_service::{Application, get_postgres_pool};
use auth_service::services::{HashmapTwoFACodeStore, HashSetBannedTokenStore, MockEmailClient, PostgresUserStore};
use auth_service::utils::constants::DATABASE_URL;
use auth_service::utils::constants::test;

pub struct TestApp {
    pub address: String,
    pub cookie_jar: Arc<Jar>,
    pub http_client: reqwest::Client,
    pub db_name: String,
    pub clean_up_called: bool,
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}

pub fn get_malformed_email() -> String {
    "example.com".to_owned()
}

impl TestApp {
    pub async fn new() -> Self {
        let db_name = Uuid::new_v4().to_string();
        let pg_pool = configure_postgresql(db_name.clone()).await;

        let app_state = AppState::new(
            Arc::new(RwLock::new(PostgresUserStore::new(pg_pool))),
            Arc::new(RwLock::new(HashSetBannedTokenStore::default())),
            Arc::new(RwLock::new(HashmapTwoFACodeStore::default())),
            Arc::new(RwLock::new(MockEmailClient::default())),
        );

        let app = Application::build(app_state, test::APP_ADDRESS)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address().to_string());

        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(async { app.run().await });

        let cookie_jar = Arc::new(Jar::default());
        let http_client = reqwest::Client::builder()
            .cookie_provider(cookie_jar.clone())
            .build()
            .unwrap();

        Self {
            address,
            cookie_jar,
            http_client,
            db_name,
            clean_up_called: false,
        }
    }

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
    where
        T: serde::Serialize,
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

    pub async fn post_verify_2fa<Body>(&self, body: &Body) -> reqwest::Response
    where Body: serde::Serialize + ?Sized
    {
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn post_verify_token<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize + ?Sized,
    {
        self.http_client
            .post(format!("{}/verify-token", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_refresh_token<T>(&self, body: &T) -> reqwest::Response
    where T: serde::Serialize + ?Sized
    {
        self.http_client
            .post(&format!("{}/refresh-token", &self.address))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .expect("Failed to send request")
    }

    pub async fn clean_up(&mut self) {
        if self.clean_up_called {
            return;
        }

        delete_database(&self.db_name).await;

        self.clean_up_called = true;
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if !self.clean_up_called {
            panic!("TestApp::clean_up was not called before dropping TestApp");
        }
    }
}

async fn configure_postgresql(db_name: String) -> PgPool {
    let postgresql_conn_url = DATABASE_URL.to_owned();

    configure_database(&postgresql_conn_url, &db_name).await;

    let postgresql_conn_url_with_db = format!("{}/{}", postgresql_conn_url, db_name);

    // Create a new connection pool and return it
    get_postgres_pool(&postgresql_conn_url_with_db)
        .await
        .expect("Failed to create Postgres connection pool!")
}

async fn configure_database(db_conn_string: &str, db_name: &str) {
    // Create database connection
    let connection = PgPoolOptions::new()
        .connect(db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Create a new database
    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to create database.");


    // Connect to new database
    let db_conn_string = format!("{}/{}", db_conn_string, db_name);

    let connection = PgPoolOptions::new()
        .connect(&db_conn_string)
        .await
        .expect("Failed to create Postgres connection pool.");

    // Run migrations against new database
    sqlx::migrate!()
        .run(&connection)
        .await
        .expect("Failed to migrate the database");
}

async fn delete_database(db_name: &str) {
    let postgresql_conn_url = DATABASE_URL.to_owned();
    println!("Dropping database: {}", db_name);

    let connection_options = PgConnectOptions::from_str(&postgresql_conn_url)
        .expect("Failed to parse PostgreSQL connection string");

    let mut connection = PgConnection::connect_with(&connection_options)
        .await
        .expect("Failed to connect to Postgres");

    // Kill active connections to the database
    connection
        .execute(
            format!(
                r#"
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{}'
                  AND pid <> pg_backend_pid();
        "#,
                db_name
            )
                .as_str(),
        )
        .await
        .expect("Failed to drop the database.");

    // Drop the database
    connection
        .execute(format!(r#"DROP DATABASE "{}";"#, db_name).as_str())
        .await
        .expect("Failed to drop the database.");
}