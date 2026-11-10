use axum::{Json, extract::State};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    axum_trait_impls::extractors::DsAccess,
    responses::error_t::InternalError,
    types::{AppState, KeyPackage, Res},
};

#[derive(Serialize)]
pub struct KeyPkgClaimResp {
    pub device_id: Uuid,
    pub key_package: String,
    pub is_last_resort: bool,
}

#[derive(Deserialize)]
pub struct KeyPkgClaimInput {
    pub user_id: Uuid,
}

pub async fn claim_key_pkg(
    device: DsAccess,
    State(mut state): State<AppState>,
    Json(data): Json<KeyPkgClaimInput>,
) -> Result<Res<Vec<KeyPkgClaimResp>>, InternalError> {
    let user_devices: Vec<KeyPackage> = state
        .pg_interface
        .select_many(Some((&["user_id"], &[data.user_id])), None)
        .await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: None,
    });
}
