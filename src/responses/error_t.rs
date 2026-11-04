#[derive(Clone)]
pub enum AuthError {
    MissingToken,
    InvalidToken,
    InvalidCredentials,
    WrongTokenType,
    ExpiredToken,
    InvalidNickname,
    InvalidPrivilige,
    SelfInvite,
    SelfOp,
    UserUnreachable,
    NonOwner,
    Blocked,
}

#[derive(Debug, PartialEq)]
pub enum InternalError {
    DbError,
    RedisError,
    DecodeEncodeErr,
    OperationsError,
    NoMatches,
    BadRequest,
    BodyTooLarge,
    UnknownType,
    EmptyMessage,
    DuplicateData,
    DetachedOwner,
    Invalidlifetime,
    DetachingOperation,
    InvalidAccountCredentials,
    MiscellaneousInternalError,
}

pub enum GenericErr {
    Auth(AuthError),
    Internal(InternalError),
}
