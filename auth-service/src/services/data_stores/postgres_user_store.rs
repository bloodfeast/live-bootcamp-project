use std::error::Error;
use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    PasswordVerifier, Version,
};

use sqlx::PgPool;

use crate::domain::{Email, User, UserStore, UserStoreError, Password, FromDbString};

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
        let password_hash = compute_password_hash(user.password.as_ref().to_owned())
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        println!("email: {:?}", user.email.as_ref());
        println!("password_hash: {:?}", password_hash);
        println!("requires_2fa: {:?}", user.requires_2fa);
        println!("--------------------------------------");

        sqlx::query!(
            r#"
            INSERT INTO users (email, password_hash, requires_2fa)
            VALUES ($1, $2, $3)
            "#,
            user.email.as_ref().to_string(),
            &password_hash,
            user.requires_2fa
        )
            .execute(&self.pool)
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?;

        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        sqlx::query!(
            r#"
            SELECT email, password_hash, requires_2fa
            FROM users
            WHERE email = $1
            "#,
            email.as_ref().to_string()
        )
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?
            .map(|row| {
                println!("email: {:?}", &row.email);
                println!("password_hash: {:?}", &row.password_hash);
                println!("requires_2fa: {:?}", &row.requires_2fa);
                Ok(User {
                    email: Email::from_db_string(&row.email),
                    password: Password::from_db_string(&row.password_hash),
                    requires_2fa: row.requires_2fa,
                })
            })
            .ok_or(UserStoreError::UserNotFound)?
    }

    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let user = self.get_user(email).await?;

        verify_password_hash(
            user.password.as_ref().to_owned(),
            password.as_ref().to_owned(),
        )
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}

async fn verify_password_hash(
    expected_password_hash: String,
    password_candidate: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    tokio::task::spawn_blocking(move || {
        let expected_password_hash: PasswordHash<'_> = PasswordHash::new(&expected_password_hash)?;

        Argon2::default()
            .verify_password(password_candidate.as_bytes(), &expected_password_hash)
            .map_err(|e| e.into())
    }).await?
}

async fn compute_password_hash(password: String) -> Result<String, Box<dyn Error + Send + Sync>> {
    tokio::task::spawn_blocking(move || {
        let salt: SaltString = SaltString::generate(&mut rand::thread_rng());
        let password_hash = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None)?,
        )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

        Ok(password_hash)
    }).await?
}