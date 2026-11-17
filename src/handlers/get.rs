use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::Engine;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::types::Group_Info;
use crate::{
    axum_trait_impls::extractors::DsAccess,
    responses::error_t::InternalError,
    types::{
        AppState, B64_ENGINE, Group, Key_Package, LogKind, LogicalOp, Mailbox_Ack, Mailbox_Item,
        MailboxKind, PLACE_HOLDER_TIME, Res,
    },
};

#[derive(Serialize)]
pub struct PkgsResp {
    pub avalible: i64,
    pub has_last_resort: bool,
}

#[derive(Serialize)]
pub struct GroupInfoResp {
    pub infos: Vec<GroupInfoElement>,
    pub pin: Option<i64>,
}
#[derive(Serialize)]
pub struct GroupInfoElement {
    pub seq: i64,
    pub epoch: i64,
    pub group_info: String,
}

#[derive(Deserialize)]
pub struct GroupFromPaths {
    pub group_id: Uuid,
    pub from: Option<i64>,
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
pub struct MailboxItem {
    pub id: Uuid,
    pub kind: MailboxKind,
    pub payload: String,
    pub ord: i64,
}

#[derive(Serialize)]
pub struct MailboxPage {
    pub items: Vec<MailboxItem>,
    pub pin: Option<i64>,
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
            LogicalOp::AND,
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
    Path(paths): Path<GroupFromPaths>,
) -> Result<Res<GroupInfoResp>, InternalError> {
    let pin = if let Some(from) = paths.from { from } else { 0 };

    struct RawInfos {
        pub seq: i64,
        pub epoch: i64,
        pub groupinfo: Vec<u8>,
    }

    let group_infos_raw_query = sqlx::query_as!(
        RawInfos,
        "SELECT seq, epoch, groupinfo
        FROM group_infos 
        WHERE group_id = $1 AND seq >= $2 
        ORDER BY seq ASC LIMIT 501",
        paths.group_id,
        pin
    );

    let group_infos_raw = state
        .pg_interface
        .generic_fetch(group_infos_raw_query)
        .await?;

    let mut res_vec: Vec<GroupInfoElement> = group_infos_raw
        .into_iter()
        .map(|raw| GroupInfoElement {
            seq: raw.seq,
            epoch: raw.epoch,
            group_info: B64_ENGINE.encode(raw.groupinfo),
        })
        .collect();

    let next_pin = if res_vec.len() == 501 {
        Some(res_vec.pop().ok_or(InternalError::NoMatches)?.seq)
    } else {
        None
    };

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(GroupInfoResp {
            infos: res_vec,
            pin: next_pin,
        }),
    });
}

pub async fn get_group_logs(
    Path(paths): Path<GroupFromPaths>,
    State(mut state): State<AppState>,
) -> Result<Res<LogsResp>, InternalError> {
    let pin: i64 = if let Some(from) = paths.from { from } else { 0 };

    let query = sqlx::query_as!(
        LogEntryByteArray,
        r#"SELECT
        seq, epoch, kind AS "kind: LogKind", payload, created_at
        FROM group_logs
        WHERE seq >= $1 AND group_id = $2
        ORDER BY seq ASC
        LIMIT 501"#,
        pin,
        paths.group_id
    );

    let raw_bytes_version = state.pg_interface.generic_fetch(query).await?;

    let mut logs: Vec<LogEntry> = raw_bytes_version
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

    let pin: Option<i64> = if logs.len() == 501 {
        Some(logs.pop().ok_or(InternalError::NoMatches)?.seq)
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
) -> Result<Res<MailboxPage>, InternalError> {
    let offset: i64 = if let Some(path) = seq
        && let Path(num) = path
    {
        num
    } else {
        0
    };

    let items_query = sqlx::query_as!(
        Mailbox_Item,
        r#"
        SELECT 
        id, ord, commit_id, recipient_user, recipient_device, kind AS "kind: MailboxKind",
        payload, sender_user, sender_device, created_at
        FROM mailbox_items
        WHERE ord >= $1 AND recipient_user = $2
        ORDER BY ord ASC
        "#,
        offset,
        device.user_id,
    );

    let relevant_items = state.pg_interface.generic_fetch(items_query).await?;
    let relevant_item_ids: Vec<Uuid> = relevant_items.iter().map(|item| item.id).collect();
    let relevant_acks: Vec<Mailbox_Ack> = state
        .pg_interface
        .select_many(
            Some((&["item_id"], &relevant_item_ids)),
            LogicalOp::IN,
            None,
        )
        .await?;

    let mut response_items: Vec<MailboxItem> = Vec::with_capacity(501);
    let mut not_acknowledged_items: Vec<Mailbox_Ack> = Vec::new();
    let mut acks: HashSet<(Uuid, Uuid)> = HashSet::new();

    let mut pin: Option<i64> = None;

    for ack in relevant_acks {
        acks.insert((ack.item_id, ack.device_id));
    }

    for item in relevant_items {
        if response_items.len() == 501 {
            let last = response_items.pop().ok_or(InternalError::NoMatches)?;
            pin = Some(last.ord);
            break;
        }

        if let Some(_recipient) = item.recipient_device {
            response_items.push(MailboxItem {
                id: item.id,
                kind: item.kind,
                payload: B64_ENGINE.encode(item.payload),
                ord: item.ord,
            });
        } else if !acks.contains(&(item.id, device.device_id)) {
            not_acknowledged_items.push(Mailbox_Ack {
                item_id: item.id,
                device_id: device.device_id,
                acked_at: PLACE_HOLDER_TIME,
            });

            response_items.push(MailboxItem {
                id: item.id,
                kind: item.kind,
                payload: B64_ENGINE.encode(item.payload),
                ord: item.ord,
            });
        }
    }

    state
        .pg_interface
        .insert_many(&not_acknowledged_items, crate::types::BindVal::ND)
        .await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(MailboxPage {
            items: response_items,
            pin: pin,
        }),
    });
}
