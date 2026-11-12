use axum::{Json, extract::State};
use base64::Engine;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    axum_trait_impls::extractors::DsAccess,
    responses::error_t::InternalError,
    types::{AppState, B64_ENGINE, Key_Package, LogicalOp, PLACE_HOLDER_TIME, Res},
};

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
    Json(data): Json<KeyPackageInput>,
) -> Result<Res<KeyPackagesResp>, InternalError> {
    let mut tr = state.pg_interface.begin_transaction().await?;

    tr.delete_matches::<Uuid, Key_Package>(
        &["user_id", "device_id"],
        &vec![device.user_id, device.device_id],
        LogicalOp::AND,
    )
    .await?;

    let base_packages: Vec<Key_Package> = data
        .key_packages
        .into_iter()
        .map(|pkg| {
            Ok(Key_Package {
                id: 0,
                user_id: device.user_id,
                device_id: device.device_id,
                key_package: B64_ENGINE
                    .decode(pkg)
                    .map_err(|_| InternalError::DecodeEncodeErr)?,
                is_last_resort: false,
                created_at: PLACE_HOLDER_TIME,
            })
        })
        .collect::<Result<Vec<Key_Package>, InternalError>>()?;

    tr.insert_many(&base_packages, crate::types::BindVal::ND)
        .await?;
    let last_resort = Key_Package {
        id: 0,
        user_id: device.user_id,
        device_id: device.device_id,
        key_package: B64_ENGINE
            .decode(data.last_resort)
            .map_err(|_| InternalError::DecodeEncodeErr)?,
        is_last_resort: true,
        created_at: PLACE_HOLDER_TIME,
    };

    tr.insert_one(last_resort, crate::types::BindVal::ND)
        .await?;

    tr.commit().await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(KeyPackagesResp {
            stored: (base_packages.len() + 1) as i64,
            avalible: (base_packages.len() + 1) as i64,
        }),
    });
}
