use std::fmt::{Debug, Display};
use std::str::FromStr;
use super::{Email, Password, User};

#[derive(Debug, PartialEq)]
pub enum UserStoreError {
    UserAlreadyExists,
    UserNotFound,
    InvalidCredentials,
    UnexpectedError,
    TokenBanned,
}
#[derive(Debug, PartialEq)]
pub enum TwoFACodeStoreError {
    LoginAttemptIdNotFound,
    UnexpectedError,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId
where
    Self: Sized + Send + Sync + Clone + 'static,
{
    pub fn parse(id: String) -> Result<Self, String> {
        uuid::Uuid::parse_str(&id)
            .map(|_| Self(id))
            .map_err(|_| "Invalid LoginAttemptId".to_string())
    }
}

impl FromStr for LoginAttemptId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s.to_string())
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
    pub fn parse(code: String) -> Result<Self, String> {
        if code.len() == 6 && code.chars().all(|c| c.is_digit(10)) {
            Ok(Self(code))
        } else {
            Err("Invalid TwoFACode".to_string())
        }
    }
}

impl FromStr for TwoFACode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s.to_string())
    }
}

impl AsRef<str> for TwoFACode {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
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
    async fn add_banned_token(&mut self, token: String) -> Result<(), UserStoreError>;
    async fn is_banned(&self, token: &str) -> Result<bool, UserStoreError>;
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
