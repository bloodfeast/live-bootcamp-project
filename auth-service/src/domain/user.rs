use std::str::FromStr;
// auth-service/src/domain/user.rs
use crate::domain::AuthAPIError;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct Email {
    email: String,
    is_valid: bool,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct Password {
    password: String,
    is_valid: bool,
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.email
    }
}
impl FromStr for Email {
    type Err = AuthAPIError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let is_valid = !s.is_empty() && validator::ValidateEmail::validate_email(&s);
        if !is_valid {
            return Err(AuthAPIError::InvalidCredentials);
        };
        Ok(Email {
            email: s.to_string(),
            is_valid: false,
        })
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.password
    }
}

impl FromStr for Password {
    type Err = AuthAPIError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let is_valid = validate_password(&s);

        if !is_valid {
            return Err(AuthAPIError::InvalidCredentials);
        };

        Ok(Password {
            password: s.to_string(),
            is_valid: false,
        })
    }
}


fn validate_password(password: &str) -> bool {
    let length_check = validator::ValidateLength::validate_length(password, Some(8), Some(32), None);
    if !length_check {
        return false;
    }
    let valid_chars = validator::ValidateNonControlCharacter::validate_non_control_character(&password);
    if !valid_chars {
        return false;
    }
    true
}

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub email: Email,
    pub password: Password,
    requires_2fa: bool,
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