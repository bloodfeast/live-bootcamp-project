use std::sync::Arc;

use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use crate::domain::{Email, FromDbString, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

#[derive(Clone)]
pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore{
    async fn add_code(
        &mut self,
        email: &Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>
    {
        let key = get_key(&email);
        let two_fa_tuple = TwoFATuple(login_attempt_id.as_ref().to_string(), code.to_string());
        let json = serde_json::to_string(&two_fa_tuple).map_err(|_| TwoFACodeStoreError::UnexpectedError)?;
        let mut conn = self.conn.write().await;
        conn.set_ex(key, json, TEN_MINUTES_IN_SECONDS)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        let key = get_key(email);
        let mut conn = self.conn.write().await;
        conn.del(key)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        let key = get_key(email);
        let mut conn = self.conn.write().await;
        let json: String = conn.get(key)
            .map_err(|_| TwoFACodeStoreError::LoginAttemptIdNotFound)?;

        let TwoFATuple(login_attempt_id, code) = serde_json::from_str(&json)
            .map_err(|_| TwoFACodeStoreError::UnexpectedError)?;

        Ok((
            LoginAttemptId::from_db_string(&login_attempt_id),
            TwoFACode::parse(code)
                .map_err(|_| TwoFACodeStoreError::UnexpectedError)?
        ))
    }
}

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}
