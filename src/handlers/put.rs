use axum::{Json, extract::State};
use base64::Engine;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{axum_trait_impls::extractors::DsAccess, responses::error_t::InternalError, types::{AppState, B64_ENGINE, KeyPackage, Res}};

#[derive(Deserialize)]
pub struct KeyPackageInput {
    pub key_packages: Vec<String>,
    pub last_resort: String,
}

#[derive(Serialize)]
pub struct KeyPackagesResp {
    pub stored: i64,
    pub avalible: i64,
}

pub async fn put_keypackages(
    device: DsAccess,
    State(mut state): State<AppState>,
    Json(data): Json<KeyPackageInput>
) -> Result<Res<KeyPackagesResp>, InternalError> {
    let mut tr = state.pg_interface.begin_transaction().await?;

    let package_deletes: Vec<KeyPackage> = tr.delete_many(&["user_id", "device_id"], &[device.user_id, device.device_id]).await?;

    let base_packages: Vec<KeyPackage> = data.key_packages.into_iter().map(|pkg| Ok(KeyPackage {
        id: 0,
        user_id: device.user_id,
        device_id: device.device_id,
        key_package: B64_ENGINE.decode(pkg).map_err(|_| InternalError::DecodeEncodeErr)?,
        is_last_resort: false,
        created_at: OffsetDateTime::now_utc()

    })).collect::<Result<Vec<KeyPackage>, InternalError>>()?;

    return Err(InternalError::BadRequest);
}