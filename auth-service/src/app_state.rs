use std::sync::Arc;
use tokio::sync::RwLock;
use crate::domain::UserStore;

/// The `AppState` struct holds the application state.
/// It contains a reference to the user store.
///
/// The `AppState` struct is generic over the type `T`, which must implement the `UserStore` trait.
/// I opted to use a generic implementation here instead of a trait object because it allows us to
/// specify the concrete type of the user store at compile time.
///
/// - This implementation also adds a `Clone` bound to the `T` type parameter. \
/// \
/// This is in addition to the `UserStore` trait bound. \
/// which already implements `Sized`, `Send`, and `Sync` \
/// **see also: [domain/data_stores.rs](crate::domain::data_stores::UserStore)**
///
/// ###### Pros:
/// - The compiler can optimize the code better due
/// to the concrete type being known at compile time.
///
/// ###### Cons:
/// - It requires more boilerplate code, which could be a bit cumbersome later
/// if we have a lot of different types that implement the `UserStore` trait.
///
#[derive(Clone)]
pub struct AppState<T: UserStore> {
    pub user_store: Arc<RwLock<T>>,
}

impl <T>AppState<T>
where T: UserStore + Clone,
{
    pub fn new(user_store: Arc<RwLock<T>>) -> Self {
        Self { user_store }
    }
}