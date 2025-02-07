use std::sync::Arc;
use sqlx::PgPool;
use tokio::sync::RwLock;

use auth_service::app_state::AppState;
use auth_service::services::{HashmapTwoFACodeStore, HashmapUserStore, HashSetBannedTokenStore, MockEmailClient, PostgresUserStore};
use auth_service::{Application, get_postgres_pool};
use auth_service::utils::constants::env::DATABASE_URL;
use auth_service::utils::constants::prod;

#[tokio::main]
async fn main() {

    let pg_pool = configure_postgresql().await;

    let app_state = AppState::new(
        Arc::new(RwLock::new(PostgresUserStore::new(pg_pool))),
        Arc::new(RwLock::new(HashSetBannedTokenStore::default())),
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