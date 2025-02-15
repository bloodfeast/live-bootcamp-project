use std::sync::Arc;
use sqlx::PgPool;
use tokio::sync::RwLock;

use auth_service::app_state::AppState;
use auth_service::services::{HashmapTwoFACodeStore, MockEmailClient, PostgresUserStore, RedisBannedTokenStore};
use auth_service::{Application, get_postgres_pool, get_redis_client};
use auth_service::utils::constants::{DATABASE_URL, REDIS_HOST_NAME};
use auth_service::utils::constants::prod;
use auth_service::utils::init_tracing;

#[tokio::main]
async fn main() {
    color_eyre::install()
        .expect("Failed to install color_eyre");

    init_tracing().expect("Failed to initialize tracing");

    let pg_pool = configure_postgresql().await;

    let app_state = AppState::new(
        Arc::new(RwLock::new(PostgresUserStore::new(pg_pool))),
        Arc::new(RwLock::new(RedisBannedTokenStore::new(Arc::new(RwLock::new(configure_redis()))))),
        Arc::new(RwLock::new(HashmapTwoFACodeStore::default())),
        Arc::new(RwLock::new(MockEmailClient::default())),
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
async fn configure_postgresql() -> PgPool {
    // Create a new database connection pool
    let pg_pool = get_postgres_pool(&DATABASE_URL)
        .await
        .expect("Failed to create Postgres connection pool!");

    // Run database migrations against our test database!
    sqlx::migrate!()
        .run(&pg_pool)
        .await
        .expect("Failed to run migrations");

    pg_pool
}
fn configure_redis() -> redis::Connection {
    get_redis_client(REDIS_HOST_NAME.to_owned())
        .expect("Failed to get Redis client")
        .get_connection()
        .expect("Failed to get Redis connection")
}