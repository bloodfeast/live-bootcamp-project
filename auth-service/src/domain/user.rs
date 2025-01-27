use crate::domain::{AuthAPIError, Password, Email};

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub email: Email,
    pub password: Password,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: Password, requires_2fa: bool) -> Result<User, AuthAPIError> {
        Ok(Self {
            email,
            password,
            requires_2fa,
        })
    }
}