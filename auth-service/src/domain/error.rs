use color_eyre::eyre::Report;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthAPIError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
    #[error("Missing Token")]
    MissingToken,
    #[error("Invalid Token")]
    InvalidToken,
    #[error("Malformed Request")]
    MalformedRequest,
}