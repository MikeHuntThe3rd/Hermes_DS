use axum::extract::State;
use reqwest::StatusCode;
use serde::Serialize;

use crate::{
    axum_trait_impls::extractors::DsAccess,
    responses::error_t::InternalError,
    types::{AppState, KeyPackage, Res},
};

#[derive(Serialize)]
pub struct PkgsResp {
    pub avalible: i64,
    pub has_last_resort: bool,
}

pub async fn get_key_pkgs(
    device: DsAccess,
    State(mut state): State<AppState>,
) -> Result<Res<PkgsResp>, InternalError> {
    let key_pkgs: Vec<KeyPackage> = state
        .pg_interface
        .select_many(
            Some((
                &["user_id", "device_id"],
                &[device.user_id, device.device_id],
            )),
            None,
        )
        .await?;
    let mut has_last_res = false;
    for pkg in &key_pkgs {
        if pkg.is_last_resort {
            has_last_res = true;
            break;
        }
    }

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(PkgsResp {
            avalible: key_pkgs.len() as i64,
            has_last_resort: has_last_res,
        }),
    });
}
