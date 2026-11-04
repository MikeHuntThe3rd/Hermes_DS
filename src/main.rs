mod axum_trait_impls;
mod certificates;
mod db;
mod handlers;
mod responses;
mod types;

use std::{env, sync::Arc, time::Duration, vec};

use axum::{
    Router,
    http::{Method, StatusCode, header},
    routing::{delete, get, patch, post},
};

use base64::Engine;
use ed25519_dalek::SigningKey;
use fred::{
    interfaces::ClientLike,
    types::{
        Builder,
        config::{Config, TcpConfig},
    },
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

use crate::{
    certificates::intermediate_keys::Pki,
    db::DbInterface,
    handlers::{
        delete::{delete_self, revoke_device},
        get::{
            get_deletions_from, get_devices, get_initial_deletions, get_intermediate_keys,
            get_jwt_okp_keys, get_signed_devices, get_user_profile, get_users_by_username,
        },
        patch::update_self,
        post::*,
    },
    responses::error_t::InternalError,
    types::{B64_ENGINE, JwtSignerKey, PLACE_HOLDER_UUID, Res},
};
use crate::{handlers::get::get_signed_ds_eps, types::PrivilegeT};
use types::{AppState, User};

async fn ensure_master_user(mut state: AppState) {
    let (usr_nm, pswrd) = (
        env::var("M_USERNAME").expect("the variable for the master user's username is expected"),
        env::var("M_PASSWORD").expect("the variable for the master user's password is expected"),
    );

    let user = state
        .pg_interface
        .select_one::<String, User>((
            &["username", "password"],
            &vec![usr_nm.clone(), pswrd.clone()],
        ))
        .await;

    let master_user = User {
        id: PLACE_HOLDER_UUID,
        prv: PrivilegeT::Proprietor,
        home_ds: Uuid::new_v4(),
        nickname: "master".to_string(),
        username: usr_nm,
        password: pswrd,
        changes: 0,
        pfp: None,
    };

    match user {
        Ok(u) if u.prv != PrivilegeT::Proprietor => {
            state
                .pg_interface
                .delete_many::<Uuid, User>(&[u.id])
                .await
                .expect("generic db ops are expected to succeed");
            state
                .pg_interface
                .insert_one(master_user, false)
                .await
                .expect("generic db ops are expected to succeed");
        }
        Err(e) if e == InternalError::NoMatches => {
            state
                .pg_interface
                .insert_one(master_user, false)
                .await
                .expect("generic db ops are expected to succeed");
        }
        Err(_) => {
            panic!("generic db ops are expected to succeed")
        }
        _ => {}
    }
}

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

    let secret_bytes: [u8; 32] = env::var("SECRET")
        .expect("the jwt secret is expected to exist")
        .into_bytes()
        .try_into()
        .expect("the string needs to be serializable to a size 32 byte array");

    let signer = SigningKey::from_bytes(&secret_bytes);

    let state = AppState {
        secret_b_array: Arc::new(secret_bytes),
        jwt_okp: Arc::new(JwtSignerKey {
            kid: Uuid::new_v4(),
            kty: "OKP".to_string(),
            alg: "EdDSA".to_string(),
            crv: "Ed25519".to_string(),
            usage: "sig".to_string(),
            x: B64_ENGINE.encode(signer.verifying_key().as_bytes()),
            signer: signer,
        }),
        pg_interface: DbInterface::new(db_conn_pool)
            .await
            .expect("failed to create the postgres db connection"),
        kvs_client: kv_client,
        pki: Pki {
            intermediates: Arc::new(Vec::new()),
        },
    };

    ensure_master_user(state.clone()).await;

    return state;
}

async fn palceholder_handler() -> Res<()> {
    Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: None,
    }
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

    let auth: Router<AppState> = Router::new()
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/sign_up", post(sign_up))
        .route("/invite_new_user", post(create_new_user_invite))
        .route("/ds-token", post(mint_ds_token));

    let devices: Router<AppState> = Router::new()
        .route("/register", post(add_device))
        .route("/all", get(get_devices))
        .route("/{device_id}", delete(revoke_device));

    let users: Router<AppState> = Router::new()
        .route("/me", delete(delete_self))
        .route("/me", patch(update_self))
        .route("/{user_id}/profile", get(get_user_profile))
        .route("/{user_id}/devices", get(get_signed_devices))
        .route("/lookup/{nickname}", get(get_users_by_username));

    let pki: Router<AppState> = Router::new()
        .route("/intermediates", get(get_intermediate_keys))
        .route("/JWKS", get(get_jwt_okp_keys));

    let dir: Router<AppState> = Router::new()
        .route("/ds-providers", get(get_signed_ds_eps))
        .route("/deletions/initial", get(get_initial_deletions))
        .route("/deletions/{cursor}", get(get_deletions_from));

    let api = Router::new()
        /* ===== INVITES ===== */
        .route("/invite_new_user", post(palceholder_handler))
        /* ===== AUTH ===== */
        .nest("/auth", auth)
        /* ===== USERS ===== */
        .nest("/user", users)
        /* ===== PKI ===== */
        .nest("/pki", pki)
        /* ===== DIR ===== */
        .nest("/dir", dir)
        /* ===== DEVICES ===== */
        .nest("/device", devices)
        /* ===== STATE ===== */
        .layer(cors)
        .with_state(state);

    let interface: Router<()> = Router::new().nest("/apiV1", api);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("port 8080 is required to be free");

    axum::serve(listener, interface)
        .await
        .expect("axum serve needs to start succesfully");
}
