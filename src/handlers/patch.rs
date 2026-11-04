use axum::{Json, extract::State, http::StatusCode};
use fred::{interfaces::{KeysInterface, TransactionInterface}, types::SetOptions};
use serde::Deserialize;
use time::SignedDuration;
use uuid::Uuid;

use crate::{axum_trait_impls::extractors::AuthUser, responses::error_t::{AuthError, GenericErr, InternalError}, types::{AppState, BLACKLIST_STR, Res, User}};

#[derive(Deserialize)]
pub struct StrippedUser {
  nickname: String,
  username: String,
  password: String,
  pfp: String,
  home_ds: String
}

pub async fn update_self(
    auth: AuthUser,
    State(mut state): State<AppState>,
    Json(data): Json<StrippedUser>,
) -> Result<Res<()>, GenericErr> {
    if data.nickname.trim().len() < 3 {
        return Err(GenericErr::Auth(AuthError::InvalidNickname));
    }

    if data.username.trim().len() < 3 || data.password.trim().len() < 3 {
        return Err(GenericErr::Internal(
            InternalError::InvalidAccountCredentials,
        ));
    }

    let old_user: User = state
        .pg_interface
        .select_one((&["id"], &[auth.user_id]))
        .await?;

    let kvs_tr = state.kvs_client.multi();

    if old_user.password != data.password {
        let access_revocation = format!("{}{}", BLACKLIST_STR, auth.access_jti);
        let refresh_revocation = format!("{}{}", BLACKLIST_STR, auth.refresh_jti);

        kvs_tr.set::<(), String, i8>(
            access_revocation, 
            1, 
            Some(fred::types::Expiration::EX(SignedDuration::minutes(10).whole_seconds())),
            Some(SetOptions::NX),
            false
        )
        .await.map_err(|_| GenericErr::Internal(InternalError::RedisError))?;

            kvs_tr.set::<(), String, i8>(
            refresh_revocation, 
            1, 
            Some(fred::types::Expiration::EX(SignedDuration::days(3).whole_seconds())),
            Some(SetOptions::NX),
            false
        )
        .await.map_err(|_| GenericErr::Internal(InternalError::RedisError))?;
    }

    let mut pg_tr = state.pg_interface.begin_transaction().await?;

    pg_tr
        .update_one(User {
            id: auth.user_id,
            prv: old_user.prv,
            home_ds: Uuid::new_v4(),
            nickname: data.nickname,
            username: data.username,
            password: data.password,
            changes: 0,
            pfp: Some(data.pfp),
        })
        .await
        .map_err(|_| GenericErr::Internal(InternalError::DbError))?;

    kvs_tr.exec::<()>(true).await.map_err(|_| InternalError::RedisError)?;
    pg_tr.commit().await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: None,
    });
}

