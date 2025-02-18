use std::collections::HashMap;

use crate::domain::{Email, LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError};

#[derive(Debug, Clone)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

impl Default for HashmapTwoFACodeStore {
    fn default() -> Self {
        Self {
            codes: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(&mut self, email: &Email, login_attempt_id: LoginAttemptId, code: TwoFACode) -> Result<(), TwoFACodeStoreError> {
        self.codes.insert(email.clone(), (login_attempt_id, code));
        Ok(())
    }

    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        self.codes.remove(email);
        Ok(())
    }

    async fn get_code(&self, email: &Email) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.codes.get(email).cloned().ok_or(TwoFACodeStoreError::LoginAttemptIdNotFound)
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;
    use super::*;
    use crate::domain::{Email, LoginAttemptId, TwoFACode};

    #[tokio::test]
    async fn test_add_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("someemail@somedomain.com".to_string()))
            .expect("Failed to create Email");
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        store.add_code(&email, login_attempt_id.clone(), code.clone())
            .await.expect("Failed to add code");
        let result = store.get_code(&email)
            .await.expect("Failed to get code");

        assert_eq!(&login_attempt_id, &result.0);
    }

    #[tokio::test]
    async fn test_remove_code() {
        let mut store = HashmapTwoFACodeStore::default();
        let email = Email::parse(Secret::new("someemail@somedomain.com".to_string()))
            .expect("Failed to create Email");
        let login_attempt_id = LoginAttemptId::default();
        let code = TwoFACode::default();

        store.add_code(&email, login_attempt_id.clone(), code.clone())
            .await.expect("Failed to add code");
        store.remove_code(&email)
            .await.expect("Failed to remove code");
        let result = store.get_code(&email)
            .await;

        assert!(result.is_err());
    }
}