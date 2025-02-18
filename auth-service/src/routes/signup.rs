use axum::{
    Json,
    response::IntoResponse,
    extract::State,
};
use secrecy::Secret;
use serde::{Deserialize};
use crate::{
    app_state::AppState,
    domain::{
        User,
        AuthAPIError
    },
    http_response::{
        AuthMessage
    },
};
use crate::domain::{BannedTokenStore, Email, EmailClient, Password, TwoFACodeStore, UserStore};

#[derive(Deserialize, Debug)]
pub struct SignupRequest {
    pub email: Secret<String>,
    pub password: Secret<String>,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

/// signup route handler
///
/// we also had to add the `UserStore` trait bound to the `T` type parameter,
/// so we can call the `add_user` method on the `UserStore` instance.
///
/// - see also [app_state.rs](crate::app_state::AppState)
#[tracing::instrument(name = "Signup", skip_all)]
pub async fn signup<T, U, V, W>(
    State(state): State<AppState<T, U, V, W>>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError>
where T: UserStore,
      U: BannedTokenStore,
      V: TwoFACodeStore,
      W: EmailClient
{
    let email = Email::parse(request.email)
        .map_err(|_| AuthAPIError::MalformedRequest)?;
    let password = Password::parse(request.password)
        .map_err(|_| AuthAPIError::MalformedRequest)?;

    // Create a new `User` instance using data in the `request`
    let user = User::new(email, password, request.requires_2fa)?;

    let mut user_store = state.user_store.write().await;

    if user_store.get_user(&user.email).await.is_ok() {
        return Err(AuthAPIError::UserAlreadyExists);
    }

    match user_store.add_user(user).await {
        Ok(_) => {
            Ok(AuthMessage::UserCreated.into_response())
        },
        Err(e) => Err(AuthAPIError::UnexpectedError(e.into())),
    }
}