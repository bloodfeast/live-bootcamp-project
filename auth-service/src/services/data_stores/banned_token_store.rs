use crate::domain::{BannedTokenStore, UserStoreError};
use std::collections::HashSet;
use color_eyre::eyre::eyre;
use crate::services::BannedTokenStoreError;

#[derive(Debug, Default, Clone)]
pub struct HashSetBannedTokenStore {
    banned_tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn add_banned_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        if self.banned_tokens.contains(&token) {
            return Err(BannedTokenStoreError::UnexpectedError(eyre!("Token already banned")));
        }
        self.banned_tokens.insert(token);
        Ok(())
    }

    async fn is_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
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