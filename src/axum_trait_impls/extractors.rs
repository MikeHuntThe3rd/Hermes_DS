use crate::types::{DsJwtClaims, Jwks, KID_STR};
use axum::{
    RequestPartsExt,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};

use fred::{interfaces::KeysInterface, types::SetOptions::NX};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use uuid::Uuid;

use crate::{responses::error_t::*, types::AppState};

#[derive(Clone)]
pub struct DsAccess {
    pub kid: Uuid,
    pub public_key_b64: String,
}

impl<T> FromRequestParts<T> for DsAccess
where
    T: Sync + Send,
    AppState: FromRef<T>,
{
    type Rejection = GenericErr;
    async fn from_request_parts(parts: &mut Parts, state: &T) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| GenericErr::Auth(AuthError::MissingToken))?;

        let app_state = AppState::from_ref(state);

        let header = decode_header(bearer.token()).map_err(|_| InternalError::DecodeEncodeErr)?;
        let kid = header.kid.ok_or(InternalError::DecodeEncodeErr)?;
        let public_key_b64 = app_state
            .kvs_client
            .get::<Option<String>, String>(format!("{KID_STR}{kid}"))
            .await
            .map_err(|_| InternalError::RedisError)?;

        let decode_key = if let Some(public_key) = public_key_b64 {
            DecodingKey::from_ed_components(&public_key)
            .map_err(|_| InternalError::DecodeEncodeErr)?
        }
        else {
        };


        let tkn_data = decode::<DsJwtClaims>(
            bearer.token(),
            &decode_key,
            &Validation::new(jsonwebtoken::Algorithm::EdDSA),
        )
        .map_err(|_| GenericErr::Auth(AuthError::InvalidToken))?;

        return Ok(DsAccess {
            kid: Uuid::new_v4(),
            public_key_b64: String::new(),
        });
    }
}

async fn sync_kvs_to_known_jwks(state: &AppState) -> Result<(), InternalError> {
    let resp_body = state.http_client.get("url").send()
    .await.map_err(|_| InternalError::OperationsError)?
    .text().await.map_err(|_| InternalError::OperationsError)?;

    let jwks: Vec<Jwks> = serde_json::de::from_str(&resp_body)
    .map_err(|_| InternalError::DecodeEncodeErr)?;

    for jwk in jwks {
        let sig: Option<String> = state.kvs_client.get(format!("{KID_STR}{}", jwk.kid)).await.map_err(|_| InternalError::RedisError)?;
        if sig.is_none() {
            state.kvs_client.set::<i8, String, String>(format!("{KID_STR}{}", jwk.kid), jwk.x, None, Some(NX), false)
            .await.map_err(|_| InternalError::RedisError)?;
        }
    }
    return Ok(());
}
