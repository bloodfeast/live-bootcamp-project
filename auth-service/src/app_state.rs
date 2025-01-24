use std::sync::Arc;
use tokio::sync::RwLock;
use crate::domain::{BannedTokenStore, UserStore};

/// The `AppState` struct holds the application state.
/// It contains a reference to the user store.
///
/// The `AppState` struct is generic over the type `T`, which must implement the `UserStore` trait. \
/// *I opted to use a generic implementation here instead of a trait object because it allows us to
/// specify the concrete type of the user store at compile time.*
///
/// - This implementation also adds a `Clone` bound to the `T` type parameter which allows us to
/// wrap the `UserStore` in an `Arc` smart pointer with a `RwLock` to allow for concurrent access.\
/// \
/// This is in addition to the `UserStore` trait bound. \
/// which already implements `Sized`, `Send`, and `Sync` \
/// \
/// **see also: [domain/data_stores.rs](crate::domain::data_stores::UserStore)**
///
/// ###### Pros:
/// - The compiler can optimize the code better due
/// to the concrete type being known at compile time.
///
/// ###### Cons:
/// - It requires more boilerplate code, which could be a bit cumbersome later
/// if we have a lot of different types that implement the `UserStore` trait with different
/// trait bound requirements. \
/// **see: [Application::build](crate::Application::build)**
///
#[derive(Clone)]
pub struct AppState<T: UserStore, U: BannedTokenStore> {
    pub user_store: Arc<RwLock<T>>,
    pub banned_token_store: Arc<RwLock<U>>,
}

impl <T, U>AppState<T, U>
where T: UserStore + Clone,
      U: BannedTokenStore + Clone
{
    pub fn new(user_store: Arc<RwLock<T>>, banned_token_store: Arc<RwLock<U>>) -> Self {
        Self { user_store, banned_token_store }
    }
}