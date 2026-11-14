use axum::extract::{Path, State, path};
use base64::Engine;
use fred::util::NONE;
use reqwest::StatusCode;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    axum_trait_impls::extractors::DsAccess, responses::error_t::InternalError, types::{AppState, B64_ENGINE, Group, Key_Package, LogKind, Mailbox_Item, MailboxKind, Res},
};

#[derive(Serialize)]
pub struct PkgsResp {
    pub avalible: i64,
    pub has_last_resort: bool,
}

#[derive(Serialize)]
pub struct GroupInfoResp {
    pub epoch: i64,
    pub group_info: String,
}

#[derive(Serialize)]
pub struct LogEntry {
    pub seq: i64,
    pub epoch: i64,
    pub kind: LogKind,
    pub payload: String,
    pub created_at: OffsetDateTime,
}

pub struct LogEntryByteArray {
    pub seq: i64,
    pub epoch: i64,
    pub kind: LogKind,
    pub payload: Vec<u8>,
    pub created_at: OffsetDateTime,
}

#[derive(Serialize)]
pub struct LogsResp {
    pub logs: Vec<LogEntry>,
    pub pin: Option<i64>,
}

#[derive(Serialize)]
pub struct MailboxItem{
    pub id: Uuid,
    pub kind: MailboxKind,
    pub payload: String,
    pub ord: i64,
}

pub struct RawMailboxItem{
    pub id: Uuid,
    pub kind: MailboxKind,
    pub payload: Vec<u8>,
    pub ord: i64,
    pub recipient_device: Option<Uuid>,
}

#[derive(Serialize)]
pub struct MailboxPage{
    pub items: Vec<MailboxItem>,
    pub has_more: bool,
    pub pin: Option<i64>
}

pub async fn get_key_pkgs(
    device: DsAccess,
    State(mut state): State<AppState>,
) -> Result<Res<PkgsResp>, InternalError> {
    let key_pkgs: Vec<Key_Package> = state
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

pub async fn get_group_info(
    _device: DsAccess,
    State(mut state): State<AppState>,
    Path(group_id): Path<Uuid>,
) -> Result<Res<GroupInfoResp>, InternalError> {
    let group: Group = state
        .pg_interface
        .select_one((&["id"], &[group_id]))
        .await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(GroupInfoResp {
            epoch: group.epoch,
            group_info: B64_ENGINE.encode(group.groupinfo),
        }),
    });
}

pub async fn get_group_logs(
    Path(group_id): Path<Uuid>,
    seq: Option<Path<i64>>,
    State(mut state): State<AppState>,
) -> Result<Res<LogsResp>, InternalError> {
    let offset: i64 = if let Some(path) = seq && let Path(num) = path{
        num
    }else{
        0
    };

    let query = sqlx::query_as!(
        LogEntryByteArray,
        r#"SELECT 
    seq, epoch, kind AS "kind: LogKind", payload, created_at 
    FROM group_logs
        WHERE seq > $1 AND group_id = $2
        ORDER BY seq ASC
        LIMIT 500"#,
        offset,
        group_id
    );

    let raw_bytes_version = state.pg_interface.generic_fetch(query).await?;

    let logs: Vec<LogEntry> = raw_bytes_version
    .into_iter()
    .map(|raw| {
        Ok(LogEntry {
            seq: raw.seq,
            epoch: raw.epoch,
            kind: raw.kind,
            payload: B64_ENGINE.encode(raw.payload),
            created_at: raw.created_at,
        })
    })
    .collect::<Result<Vec<LogEntry>, InternalError>>()?;

    let pin: Option<i64> = if logs.len() == 500
        && let Some(last_log) = logs.iter().next_back()
    {
        Some(last_log.seq)
    } else {
        None
    };

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(LogsResp { logs, pin }),
    });
}

pub async fn get_mailbox(
    device: DsAccess,
    seq: Option<Path<i64>>,
    State(mut state): State<AppState>,
) -> Result<Res<MailboxPage>, InternalError>{
    let offset: i64 = if let Some(path) = seq && let Path(num) = path{
        num
    }
    else {
        0
    };

    let query = sqlx::query_as!(
        RawMailboxItem,
        r#"SELECT 
    id, ord, kind AS "kind: MailboxKind", payload, recipient_device
    FROM mailbox_items
        WHERE ord > $1 AND recipient_user = $2
        ORDER BY ord ASC
        LIMIT 500"#,
        offset,
        device.user_id
    );

    let raw_bytes_version = state.pg_interface.generic_fetch(query).await?;

    let mailbox_items: Vec<MailboxItem> = raw_bytes_version
    .into_iter()
    .map(|raw| {
        Ok(MailboxItem {
            id: raw.id,
            kind: raw.kind,
            payload: B64_ENGINE.encode(raw.payload),
            ord: raw.ord,
        })
    })
    .collect::<Result<Vec<MailboxItem>, InternalError>>()?;

    let mut has_more = false;
    if mailbox_items.len() > 500{
        has_more = true;
    }

    let pin: Option<i64> = if mailbox_items.len() == 500
        && let Some(last_log) = mailbox_items.iter().next_back()
    {
        Some(last_log.ord)
    } else {
        None
    };

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(MailboxPage {
            items: mailbox_items,
            has_more: has_more,
            pin: pin
        }),
    });
}