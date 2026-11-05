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
use time::OffsetDateTime;
use time::serde::timestamp;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use x509_cert::serial_number;

/* ===== CONSTS ===== */

pub const KID_STR: &'static str = "kid:";

pub const PLACE_HOLDER_UUID: Uuid = Uuid::nil();

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "log_kind", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum LogKind {
    Commit,
    Proposal,
    Application,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "mailbox_kind", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MailboxKind {
    Welcome,
    FriendRequest,
    FriendResponse,
    InviteAccept,
    InviteDecline,
    DeviceLink,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "blob_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum BlobStatus {
    Pending,
    Available,
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
pub struct KeyPackage {
    pub id: i64,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub key_package: Vec<u8>,
    pub is_last_resort: bool,
    #[serde(with = "time::serde::timestamp")]
    pub created_at: OffsetDateTime,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "id"]
pub struct Group {
    pub id: Uuid,
    pub epoch: i64,
    pub groupinfo: Vec<u8>,
    pub last_seq: i64,
    pub created_by_user: Uuid,
    pub created_by_device: Uuid,
    #[serde(with = "time::serde::timestamp")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::timestamp")]
    pub updated_at: OffsetDateTime,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "group_id;user_id;device_id"]
pub struct GroupMemberHint {
    pub group_id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    #[serde(with = "time::serde::timestamp")]
    pub added_at: OffsetDateTime,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "group_id;seq"]
pub struct GroupLog {
    pub group_id: Uuid,
    pub seq: i64,
    pub epoch: i64,
    pub kind: LogKind,
    pub payload: Vec<u8>,
    #[serde(with = "time::serde::timestamp")]
    pub created_at: OffsetDateTime,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "id"]
pub struct MailboxItem {
    pub id: Uuid,
    pub ord: i64,
    pub recipient_user: Uuid,
    pub recipient_device: Option<Uuid>,
    pub kind: MailboxKind,
    pub payload: Vec<u8>,
    pub sender_user: Uuid,
    pub sender_device: Uuid,
    #[serde(with = "time::serde::timestamp")]
    pub created_at: OffsetDateTime,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "item_id;device_id"]
pub struct MailboxAck {
    pub item_id: Uuid,
    pub device_id: Uuid,
    #[serde(with = "time::serde::timestamp")]
    pub acked_at: OffsetDateTime,
}

#[derive(sqlx::FromRow, Serialize, Deserialize, Bindable, Clone)]
#[ids = "id"]
pub struct Blob {
    pub id: Uuid,
    pub owner_user: Uuid,
    pub owner_device: Uuid,
    pub size_bytes: i64,
    pub checksum_sha256: Option<Vec<u8>>,
    #[serde(with = "time::serde::timestamp::option")]
    pub completed_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::timestamp")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::timestamp")]
    pub created_at: OffsetDateTime,
    pub status: BlobStatus,
}
#[derive(Clone)]
pub struct AppState {
    pub http_client: reqwest::Client,
    pub pg_interface: DbInterface<DbPool<Postgres>>,
    pub kvs_client: Client,
}

#[derive(Serialize, Deserialize)]
pub struct DsJwtClaims {
    pub sub: Uuid,
    pub aud: Uuid,
    pub device_id: Uuid,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Deserialize)]
pub struct Jwks {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub kid: Uuid,
    pub alg: String,
    #[serde(rename = "use")]
    pub usage: String,
}
