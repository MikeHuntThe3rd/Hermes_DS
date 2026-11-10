use std::collections::HashMap;

use axum::{Json, extract::State};
use base64::Engine;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    axum_trait_impls::extractors::DsAccess, responses::error_t::InternalError, types::{AppState, B64_ENGINE, KeyPackage, LogicalOp, Res},
};

#[derive(Serialize)]
pub struct KeyPkgsClaimElementResp {
    pub device_id: Uuid,
    pub key_package: String,
    pub is_last_resort: bool,
}

#[derive(Deserialize)]
pub struct KeyPkgClaimInput {
    pub user_id: Uuid,
}

pub async fn claim_key_pkg(
    _device: DsAccess,
    State(mut state): State<AppState>,
    Json(data): Json<KeyPkgClaimInput>,
) -> Result<Res<Vec<KeyPkgsClaimElementResp>>, InternalError> {
    let user_device_pkgs: Vec<KeyPackage> = state
        .pg_interface
        .select_many(Some((&["user_id"], &[data.user_id])), None)
        .await?;

    let mut key_pkgs: HashMap<Uuid, (Vec<u8>, bool, i64)> = HashMap::new();

    for pkg in user_device_pkgs {
        if let Some(key_pkg) = key_pkgs.get_mut(&pkg.device_id)
        {
            if key_pkg.1 && !pkg.is_last_resort {
                *key_pkg = (pkg.key_package, pkg.is_last_resort, pkg.id);
            }
        }
        else {
            key_pkgs.insert(pkg.device_id, (pkg.key_package, pkg.is_last_resort, pkg.id));
        }
    }

    let mut res: Vec<KeyPkgsClaimElementResp> = Vec::new();
    let mut marked_for_deletion: Vec<i64> = Vec::new();

    for pkg in key_pkgs.into_iter() {
        let is_last_resort: bool = pkg.1.1;
        if !is_last_resort {
            let pkg_id = pkg.1.2;
            marked_for_deletion.push(pkg_id);
        }

        let device_id = pkg.0;
        let key_package = B64_ENGINE.encode(pkg.1.0);

        res.push(KeyPkgsClaimElementResp { device_id, key_package, is_last_resort });
    }

    state.pg_interface.delete_matches::<i64, KeyPackage>(&["id"], &marked_for_deletion, LogicalOp::IN).await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(res),
    });
}
