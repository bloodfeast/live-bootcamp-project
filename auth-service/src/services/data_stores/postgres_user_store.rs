use std::error::Error;

use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};
use serde_json::to_string;
use sqlx::PgPool;

use crate::domain::{
    UserStore,
    UserStoreError,
    Email,
    Password,
    User,
};

#[derive(Debug, Clone)]
pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserStore for PostgresUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {

        let join_handle = tokio::task::spawn_blocking(move || {
            compute_password_hash(user.password.as_ref().to_string())
                .map_err(|e| {
                    eprintln!("Failed to hash password: {:?}", e);
                    UserStoreError::UnexpectedError
                })
        });

        let password_hash = join_handle.await
            .map_err(|e| {
                eprintln!("Failed to add user: {:?}", e);
                UserStoreError::UserAlreadyExists
            })??;

        let email = user.email.as_ref().to_string();
        let requires_2fa = user.requires_2fa;

        sqlx::query!(
            r#"
            INSERT INTO users (email, password_hash, requires_2fa)
            VALUES ($1, $2, $3)
            "#,
            email,
            password_hash,
            requires_2fa,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            eprintln!("Failed to add user: {:?}", e);
            UserStoreError::UserAlreadyExists
        })?;

        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        let user: Option<User> = sqlx::query_as!(
            User,
            r#"
            SELECT email, password_hash as password, requires_2fa
            FROM users
            WHERE email = $1
            "#,
            email.as_ref(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            eprintln!("Failed to get user: {:?}", e);
            UserStoreError::UserNotFound
        })?;

        match user {
            Some(user) => Ok(user),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    async fn validate_user(&self, email: &Email, password: &Password) -> Result<(), UserStoreError> {
        let user = sqlx::query!(
            r#"
            SELECT password_hash
            FROM users
            WHERE email = $1
            "#,
            email.as_ref().to_string(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            eprintln!("Failed to get user: {:?}", e);
            UserStoreError::UserNotFound
        })?;

        let user = match user {
            Some(user) => user,
            None => return Err(UserStoreError::UserNotFound),
        };
        let password = password.as_ref().to_string();

        tokio::task::spawn_blocking(move || {
            verify_password_hash(user.password_hash, password)
                .map_err(|e| {
                    eprintln!("Failed to validate user: {:?}", e);
                    UserStoreError::InvalidCredentials
                })
        }).await
            .map_err(|e| {
                eprintln!("Failed to validate user: {:?}", e);
                UserStoreError::InvalidCredentials
            })??;

        Ok(())
    }
}

// Helper function to verify if a given password matches an expected hash
// TODO: Hashing is a CPU-intensive operation. To avoid blocking
// other async tasks, update this function to perform hashing on a
// separate thread pool using tokio::task::spawn_blocking. Note that you
// will need to update the input parameters to be String types instead of &str
fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<(), Box<dyn Error>> {
    let expected_password_hash: PasswordHash<'_> = PasswordHash::new(expected_password_hash.as_str())?;

    Argon2::default()
        .verify_password(password_candidate.as_bytes(), &expected_password_hash)
        .map_err(|e| e.into())
}

// Helper function to hash passwords before persisting them in the database.
// TODO: Hashing is a CPU-intensive operation. To avoid blocking
// other async tasks, update this function to perform hashing on a
// separate thread pool using tokio::task::spawn_blocking. Note that you
// will need to update the input parameters to be String types instead of &str
fn compute_password_hash(password: String) -> Result<String, Box<dyn Error>> {
    let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None)?,
    )
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    Ok(password_hash)
}