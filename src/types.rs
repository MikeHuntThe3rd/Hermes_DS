#![allow(warnings)]
use std::sync::Arc;

use crate::db::*;
use axum::http::StatusCode;
use base64::engine::{GeneralPurpose, general_purpose::URL_SAFE_NO_PAD};
use derive_macros::Bindable;
use ed25519_dalek::{SigningKey, VerifyingKey};
use fred::clients::Client;
use serde::{Deserialize, Serialize};
use sqlx::{Database, Postgres, postgres::PgArguments, query::QueryAs};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use x509_cert::serial_number;

/* ===== CONSTS ===== */

pub const BLACKLIST_STR: &'static str = "jwt:blacklist:";
pub const INVITES_BLACKLIST_STR: &'static str = "jwt:blacklist:invites:";

pub const PLACE_HOLDER_UUID: Uuid = Uuid::nil();

pub const REG_LBL: &[u8] = b"herpesz-api";

pub const B64_ENGINE: GeneralPurpose = URL_SAFE_NO_PAD;

/* ===== TRAITS ===== */

pub trait Bindable<DB: Database> {
    fn table_name() -> &'static str;

    fn columns() -> &'static [&'static str];
    fn id_columns() -> &'static [&'static str];
    fn base_columns() -> &'static [&'static str];

    fn bind_values<'lftm>(
        &'lftm self,
        query: QueryAs<'lftm, DB, Self, DB::Arguments>,
        bind_val: BindVal,
    ) -> QueryAs<'lftm, DB, Self, DB::Arguments>
    where
        Self: Sized;
}

pub trait FetchableSignature {
    fn fetch_mut_kid(&mut self) -> &mut Option<Uuid>;
    fn fetch_mut_Signature(&mut self) -> &mut Option<String>;
}

/* ===== ENUMS ===== */

#[derive(PartialEq)]
pub enum BindVal {
    ID,
    BASE,
    ALL,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    Access,
    Refresh,
}

#[derive(Debug, sqlx::Type, Serialize, Deserialize, PartialEq)]
#[sqlx(type_name = "relation_t")]
pub enum RelationT {
    Friends,
    Pending,
    Blocked,
}

#[derive(Debug, sqlx::Type, Serialize, Deserialize, Clone, PartialEq)]
#[sqlx(type_name = "privilege_t")]
pub enum PrivilegeT {
    Consumer,
    Proprietor,
}

#[derive(Debug, sqlx::Type, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[sqlx(type_name = "rank_t")]
pub enum RankT {
    User,
    Admin,
    Owner,
}

#[derive(Debug, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "channel_t")]
pub enum ChannelT {
    Text,
    Voice,
}

/* ===== STRUCTS ===== */

pub struct Res<T>
where
    T: Serialize,
{
    pub status: StatusCode,
    pub success: bool,
    pub msg: String,
    pub data: Option<T>,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "id"]
pub struct Ds {
    pub id: Uuid,
    pub ep: String,
}

#[derive(Clone)]
pub struct AppState {
    pub pg_interface: DbInterface<DbPool<Postgres>>,
    pub kvs_client: Client,
}

#[derive(Serialize, Deserialize)]
pub struct DsTokenClaims {
    pub sub: Uuid,
    pub device_id: Uuid,
    pub kid: Option<Uuid>,
    pub signature: Option<String>,
    pub aud: Uuid,
    pub iat: u64,
    pub exp: u64,
}
