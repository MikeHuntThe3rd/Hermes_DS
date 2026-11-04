use axum::extract::{Path, State};
use axum::http::StatusCode;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::handlers::sign_json_object;
use crate::responses::error_t::{AuthError, GenericErr, InternalError};
use crate::{axum_trait_impls::extractors::AuthUser, types::*};

pub async fn delete_self(
    auth: AuthUser,
    State(mut state): State<AppState>,
) -> Result<Res<()>, InternalError> {
    let mut tr = state.pg_interface.begin_transaction().await?;

    tr.delete_many::<Uuid, User>(&[auth.user_id]).await?;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let imk = state.pki.get_im_key(now).ok_or(InternalError::NoMatches)?;

    let mut deletion = Deletion {
        seq: 0,
        user_id: auth.user_id,
        deleted_at: now,
        key_id: imk.key_id.clone(),
        signature: Vec::new(),
    };

    let signature = sign_json_object(&deletion, &imk.signer, "signature")?;

    deletion.signature = signature.to_vec();

    tr.insert_one(deletion, true).await?;

    tr.commit().await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: None,
    });
}

pub async fn revoke_device(
    auth: AuthUser,
    State(mut state): State<AppState>,
    Path(device_id): Path<Uuid>,
) -> Result<Res<()>, InternalError> {
    let mut device: Device = state
        .pg_interface
        .select_one((&["id"], &[device_id]))
        .await?;
    device.is_revoked = true;
    state.pg_interface.update_one(device).await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: None,
    });
}
