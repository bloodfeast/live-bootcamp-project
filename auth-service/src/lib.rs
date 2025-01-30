use std::error::Error;
use axum::{
    routing::post,
    serve::Serve,
    Router,
};
use axum::http::Method;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};

pub mod routes;
pub mod domain;
pub mod services;
pub mod app_state;
pub mod http_response;
pub mod utils;

use app_state::AppState;
use crate::domain::{BannedTokenStore, EmailClient, TwoFACodeStore, UserStore};

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
    /// We have to implement the generic trait `UserStore` for the `Application` struct.
    /// since we chose to use a generic implementation over a trait object.
    ///
    /// This also forces us to define the trait bounds for the `T` type parameter. \
    /// `UserStore` + `Clone` + `Send` + `Sync` + `'static`
    ///
    /// **see also [app_state.rs](crate::app_state::AppState)**
    pub async fn build<T, U, V, W>(app_state: AppState<T, U, V, W>, address: &str) -> Result<Self, Box<dyn Error>>
    where
        T: UserStore,
        U: BannedTokenStore,
        V: TwoFACodeStore,
        W: EmailClient
    {

        let allowed_origins = [
            "http://localhost:8000".parse()?,
            "http://142.93.14.57:8000".parse()?,
        ];

        let serve_dir =
            ServeDir::new("assets").not_found_service(ServeFile::new("assets/index.html"));

        let cors = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST])
            .allow_credentials(true)
            .allow_origin(allowed_origins);

        let router = Router::new()
            .fallback_service(serve_dir)
            .route("/signup", post(routes::signup))
            .route("/login", post(routes::login))
            .route("/logout", post(routes::logout))
            .route("/verify-2fa", post(routes::verify_2fa))
            .route("/verify-token", post(routes::verify_token))
            .route("/refresh-token", post(routes::refresh_token))
            .with_state(app_state)
            .layer(cors);

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
