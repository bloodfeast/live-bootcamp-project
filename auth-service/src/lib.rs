use std::error::Error;
use axum::{
    routing::post,
    serve::Serve,
    Router,
};
use tokio::net::TcpListener;

use tower_http::services::{ServeDir, ServeFile};

pub mod routes;
pub mod domain;
pub mod services;
pub mod app_state;
pub mod http_response;

use app_state::AppState;
use crate::domain::UserStore;

// This struct encapsulates our application-related logic.
#[derive(Debug)]
pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    address: String,
}

impl Application
{
    pub async fn build<T>(app_state: AppState<T>, address: &str) -> Result<Self, Box<dyn Error>>
    where
        T: UserStore + Clone + Send + Sync + 'static,
    {
        let serve_dir =
            ServeDir::new("assets").not_found_service(ServeFile::new("assets/index.html"));

        let router = Router::new()
            .fallback_service(serve_dir)
            .route("/signup", post(routes::signup))
            .route("/login", post(routes::login))
            .route("/logout", post(routes::logout))
            .route("/verify-2fa", post(routes::verify_2fa))
            .route("/verify-token", post(routes::verify_token))
            .with_state(app_state);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        Ok(
            Self {
                server,
                address
            }
        )
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }

    pub fn address(&self) -> &str {
        &self.address
    }
}
