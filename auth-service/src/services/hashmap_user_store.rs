use std::collections::HashMap;

use crate::domain::User;

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
}

pub fn user_store_error_to_string(error: &UserStoreError) -> String {
    match error {
        UserStoreError::UserAlreadyExists => "User already exists".to_string(),
        UserStoreError::UserNotFound => "User not found".to_string(),
        UserStoreError::InvalidCredentials => "Invalid credentials".to_string(),
        UserStoreError::UnexpectedError => "Unexpected error".to_string(),
    }
}

#[derive(Default, Debug)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
}

impl HashmapUserStore {
    pub fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Return `UserStoreError::UserAlreadyExists` if the user already exists,
        // otherwise insert the user into the hashmap and return `Ok(())`.
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    pub fn get_user(&self, email: &str) -> Result<&User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    pub fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        match self.users.get(email) {
            Some(user) => {
                if user.password == password {
                    Ok(())
                } else {
                    Err(UserStoreError::InvalidCredentials)
                }
            }
            None => Err(UserStoreError::UserNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::User;

    fn create_user_store() -> HashmapUserStore {
        HashmapUserStore::default()
    }

    fn create_test_user() -> User {
        User::new("some_email@some_domain.com".to_string(), "password123".to_string(), true)
    }

    fn add_user_to_store(store: &mut HashmapUserStore, user: User) -> Result<(), UserStoreError> {
        store.add_user(user.clone())
    }

    #[tokio::test]
    async fn test_add_user() {
        let mut store = create_user_store();
        let user = create_test_user();
        assert!(store.add_user(user.clone()).is_ok());
    }

    #[tokio::test]
    async fn test_add_user_already_exists() {
        let mut store = create_user_store();
        let user = create_test_user();

        assert!(store.add_user(user.clone()).is_ok());
        assert_eq!(store.add_user(user.clone()), Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = create_user_store();
        let user = create_test_user();
        add_user_to_store(&mut store, user.clone()).unwrap();

        assert_eq!(store.get_user(&user.email), Ok(&user));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = create_user_store();
        let user = create_test_user();
        add_user_to_store(&mut store, user.clone()).unwrap();

        assert_eq!(store.validate_user(&user.email, &user.password), Ok(()));
    }
}