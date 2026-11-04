use crate::types::{BLACKLIST_STR, INVITES_BLACKLIST_STR};
use axum::{
    RequestPartsExt,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};

use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};

use fred::interfaces::KeysInterface;
use jsonwebtoken::{DecodingKey, Validation, decode};
use uuid::Uuid;

use crate::{
    responses::error_t::*,
    types::{AppState, DsTokenClaims, TokenType},
};

#[derive(Clone)]
pub struct AuthDevice {
    pub user_id: Uuid,
    pub device_id: Uuid,
}

impl<T> FromRequestParts<T> for AuthDevice
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

        let tkn_data = decode::<AuthClaims>(
            bearer.token(),
            &DecodingKey::from_secret(&*app_state.secret_b_array),
            &Validation::default(),
        )
        .map_err(|_| GenericErr::Auth(AuthError::InvalidToken))?;

        if tkn_data.claims.tkn_type != TokenType::Access {
            return Err(GenericErr::Auth(AuthError::WrongTokenType));
        }

        let key = format!("{BLACKLIST_STR}{}", tkn_data.claims.jti);
        let is_revoked: i64 = app_state
            .kvs_client
            .exists(key)
            .await
            .map_err(|_| GenericErr::Internal(InternalError::RedisError))?;
        if is_revoked == 1 {
            return Err(GenericErr::Auth(AuthError::ExpiredToken));
        }

        let rjti = tkn_data
            .claims
            .rjti
            .ok_or(GenericErr::Internal(InternalError::DecodeEncodeErr))?;

        return Ok(AuthUser {
            user_id: tkn_data.claims.sub,
            access_jti: tkn_data.claims.jti,
            refresh_jti: rjti,
        });
    }
}
