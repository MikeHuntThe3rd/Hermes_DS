use base64::Engine;
use ed25519_dalek::{Signer};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::Serialize;
use uuid::Uuid;
use crate::{responses::error_t::InternalError, types::{AppState, B64_ENGINE, FetchableSignature}};


pub fn encode_to_jwt<C>(
    mut claims: C,
    state: &AppState
) -> Result<String, InternalError> 
where C: Serialize + FetchableSignature
{
    *claims.fetch_mut_kid() = Some(Uuid::new_v4());

    let mut json_object = serde_json::to_value(&claims).map_err(|_| InternalError::DecodeEncodeErr)?;
    
    json_object.as_object_mut().ok_or(InternalError::DecodeEncodeErr)?
    .remove("signature").ok_or(InternalError::DecodeEncodeErr)?;

    let bytes = serde_jcs::to_vec(&json_object)
    .map_err(|_| InternalError::DecodeEncodeErr)?;

    *claims.fetch_mut_Signature() = Some(
        B64_ENGINE.encode(*&state.jwt_okp.signer.sign(&bytes).to_bytes())
    );

    return Ok(
        encode(
            &Header::default(), 
            &claims, 
            &EncodingKey::from_secret(&*state.secret_b_array)
        ).map_err(|_| InternalError::DecodeEncodeErr)?);
}
