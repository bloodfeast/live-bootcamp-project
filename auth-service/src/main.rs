use std::sync::Arc;
use tokio::sync::RwLock;

use auth_service::app_state::AppState;
use auth_service::services::{HashmapUserStore, HashSetBannedTokenStore};
use auth_service::Application;
use auth_service::utils::constants::prod;

#[tokio::main]
async fn main() {
    let app_state = AppState::new(
        Arc::new(RwLock::new(HashmapUserStore::default())),
        Arc::new(RwLock::new(HashSetBannedTokenStore::default()))
    );

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
