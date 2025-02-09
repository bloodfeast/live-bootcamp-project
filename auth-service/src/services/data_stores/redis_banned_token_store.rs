use std::sync::Arc;

use redis::{Commands, Connection};
use tokio::sync::RwLock;

use crate::{
    domain::{BannedTokenStore, UserStoreError},
    utils::auth::TOKEN_TTL_SECONDS,
};

#[derive(Clone)]
pub struct RedisBannedTokenStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisBannedTokenStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl BannedTokenStore for RedisBannedTokenStore {
    async fn add_banned_token(&mut self, token: String) -> Result<(), UserStoreError> {
        let key = get_key(&token);

        let mut conn = self.conn.write().await;
        conn.set_ex(key, true, TOKEN_TTL_SECONDS as u64)
            .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn is_banned(&self, token: &str) -> Result<bool, UserStoreError> {
        let key = get_key(token);

        let mut conn = self.conn.write().await;
        let result: bool = conn.get(key)
            .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(result)
    }
}

// We are using a key prefix to prevent collisions and organize data!
const BANNED_TOKEN_KEY_PREFIX: &str = "banned_token:";

fn get_key(token: &str) -> String {
    format!("{}{}", BANNED_TOKEN_KEY_PREFIX, token)
}
