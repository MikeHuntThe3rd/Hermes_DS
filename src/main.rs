mod axum_trait_impls;
mod db;
mod handlers;
mod responses;
mod types;

use std::{env, time::Duration, vec};

use axum::{
    Router,
    http::{Method, StatusCode, header},
    routing::{delete, get, patch, post},
};

use fred::{
    interfaces::ClientLike,
    types::{
        Builder,
        config::{Config, TcpConfig},
    },
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tower_http::cors::{Any, CorsLayer};

use crate::{db::DbInterface, types::Res};
use types::AppState;

async fn setup() -> AppState {
    let db_opt = PgConnectOptions::new()
        .socket("/run/postgresql")
        .username(
            &std::env::var("PS_USERNAME").expect("a PS_USERNAME enviroment variable is expected"),
        )
        .database("records_ps");

    let db_conn_pool = PgPoolOptions::new()
        .max_connections(20)
        .connect_with(db_opt)
        .await
        .expect("connection pool initialization is expected to succeed");

    let conf =
        Config::from_url("redis://localhost:6379/1").expect("redis binding is expected to succeed");

    let kv_client = Builder::from_config(conf)
        .with_connection_config(|config| {
            config.connection_timeout = Duration::from_secs(1);
            config.tcp = TcpConfig {
                nodelay: Some(true),
                ..Default::default()
            }
        })
        .build()
        .expect("kv client construction is expected to succeed");

    kv_client
        .init()
        .await
        .expect("client init is expected to succeed");

    let state = AppState {
        http_client: reqwest::Client::builder().build().expect("http client failed to build"),
        pg_interface: DbInterface::new(db_conn_pool)
            .await
            .expect("failed to create the postgres db connection"),
        kvs_client: kv_client,
    };

    return state;
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().expect("a .env file is expected");
    let state = setup().await;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(Duration::from_secs(3600));

    let api = Router::new().layer(cors).with_state(state);

    let interface: Router<()> = Router::new().nest("/apiV1", api);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("port 8080 is required to be free");

    axum::serve(listener, interface)
        .await
        .expect("axum serve needs to start succesfully");
}
