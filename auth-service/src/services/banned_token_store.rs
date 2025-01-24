use crate::domain::{BannedTokenStore, UserStoreError};
use std::collections::HashSet;

#[derive(Debug, Default, Clone)]
pub struct HashSetBannedTokenStore {
    banned_tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn add_banned_token(&mut self, token: String) -> Result<(), UserStoreError> {
        if self.banned_tokens.contains(&token) {
            return Err(UserStoreError::TokenBanned);
        }
        self.banned_tokens.insert(token);
        Ok(())
    }

    async fn is_banned(&self, token: &str) -> Result<bool, UserStoreError> {
        Ok(self.banned_tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_banned_token_store() -> HashSetBannedTokenStore {
        HashSetBannedTokenStore::default()
    }

    #[tokio::test]
    async fn test_add_banned_token() {
        let mut store = create_banned_token_store();
        let token = "token".to_string();
        store.add_banned_token(token.clone()).await.unwrap();
        assert!(store.banned_tokens.contains(&token));
    }

    #[tokio::test]
    async fn test_is_banned() {
        let mut store = create_banned_token_store();
        let token = "token".to_string();
        store.banned_tokens.insert(token.clone());
        assert!(store.is_banned(&token).await.unwrap());
    }
}