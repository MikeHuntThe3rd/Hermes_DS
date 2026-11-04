use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

use crate::responses::error_t::InternalError;

pub mod delete;
pub mod get;
pub mod patch;
pub mod post;

fn sign_json_object<T: Serialize>(
    object: &T,
    signer: &SigningKey,
    sig_field: &str,
) -> Result<[u8; 64], InternalError> {
    let mut json_object =
        serde_json::to_value(object).map_err(|_| InternalError::DecodeEncodeErr)?;

    json_object
        .as_object_mut()
        .ok_or(InternalError::DecodeEncodeErr)?
        .remove(sig_field)
        .ok_or(InternalError::DecodeEncodeErr)?;

    let bytes = serde_jcs::to_vec(&json_object).map_err(|_| InternalError::DecodeEncodeErr)?;

    return Ok(signer.sign(&bytes).to_bytes());
}
