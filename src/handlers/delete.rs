use axum::extract::{Path, State};
use axum::http::StatusCode;
use uuid::Uuid;

use crate::{
    axum_trait_impls::extractors::DsAccess,
    responses::error_t::InternalError,
    types::{AppState, Mailbox_Item, Res},
};

pub async fn delete_mailbox_item(
    _device: DsAccess,
    State(mut state): State<AppState>,
    Path(item_id): Path<Uuid>,
) -> Result<Res<()>, InternalError> {
    state
        .pg_interface
        .delete_matches::<Uuid, Mailbox_Item>(&["id"], &vec![item_id], crate::types::LogicalOp::AND)
        .await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: None,
    });
}
