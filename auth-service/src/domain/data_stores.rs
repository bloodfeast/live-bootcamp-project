use std::fmt::{Debug, Display};
use std::str::FromStr;
use color_eyre::eyre::{Context, eyre, Result};
use thiserror::Error;
use crate::services::BannedTokenStoreError;
use super::{Email, Password, User};

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] color_eyre::eyre::Report),
    #[error("Banned token")]
    TokenBanned,
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::UserAlreadyExists, Self::UserAlreadyExists) => true,
            (Self::UserNotFound, Self::UserNotFound) => true,
            (Self::InvalidCredentials, Self::InvalidCredentials) => true,
            (Self::UnexpectedError(_), Self::UnexpectedError(_)) => true,
            (Self::TokenBanned, Self::TokenBanned) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] color_eyre::eyre::Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound) => true,
            (Self::UnexpectedError(_), Self::UnexpectedError(_)) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId
where
    Self: Sized + Send + Sync + Clone + 'static,
{
    pub fn parse(id: String) -> Result<Self> {
        let parsed_id = uuid::Uuid::parse_str(&id).wrap_err("Invalid login attempt id")?; // Updated!
        Ok(Self(parsed_id.to_string()))
    }
}

impl FromDbString for LoginAttemptId {
    fn from_db_string(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
       self.0.as_str()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFACode(String);
impl Default for TwoFACode {
    fn default() -> Self {
        // Use the `rand` crate to generate a random 2FA code.
        // The code should be 6 digits (ex: 834629)
        let code: u32 = rand::random::<u32>() % 1_000_000;
        Self(format!("{:06}", code))
    }
}

impl Display for TwoFACode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TwoFACode
where
    Self: Sized + Send + Sync + Clone + 'static,
{
    pub fn parse(code: String) -> Result<Self> {
        if code.len() == 6 && code.chars().all(|c| c.is_digit(10)) {
            Ok(Self(code))
        } else {
            Err(eyre!("Invalid 2FA code"))
        }
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

pub trait FromDbString {
    fn from_db_string(s: &str) -> Self;
}

#[async_trait::async_trait]
pub trait UserStore
where
    Self: Sized + Send + Sync + Clone + 'static,
{
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError>;
}

#[async_trait::async_trait]
pub trait BannedTokenStore
where
    Self: Sized + Send + Sync + Clone + 'static,
{
    async fn add_banned_token(&mut self, token: String) -> Result<(), BannedTokenStoreError>;
    async fn is_banned(&self, token: &str) -> Result<bool, BannedTokenStoreError>;
}

#[async_trait::async_trait]
pub trait TwoFACodeStore
where
    Self: Sized + Send + Sync + Clone + 'static,
{
    async fn add_code(
        &mut self,
        email: &Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}
