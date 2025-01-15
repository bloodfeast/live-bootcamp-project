use std::sync::Arc;
use tokio::sync::RwLock;
use crate::domain::UserStore;

// Using a type alias to improve readability!



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