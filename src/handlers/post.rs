use std::collections::HashMap;

use axum::{
    Json,
    extract::{Path, State},
};
use base64::Engine;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    axum_trait_impls::extractors::DsAccess,
    responses::error_t::InternalError,
    types::{
        AppState, B64_ENGINE, BindVal, Group, Group_Log, Group_Member_Hint, Key_Package, LogKind,
        LogicalOp, Mailbox_Item, MailboxKind, PLACE_HOLDER_TIME, PLACE_HOLDER_UUID, Res,
    },
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

#[derive(Deserialize)]
pub struct GroupMemberElement {
    pub user_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Deserialize)]
pub struct NewGroupInput {
    pub id: Uuid,
    pub group_info: String,
    pub memeber_hints: Vec<GroupMemberElement>,
}

#[derive(Deserialize)]
pub struct GroupProposalInput {
    pub epoch: i64,
    pub proposal: String,
}

#[derive(Serialize)]
pub struct SeqEpochResp {
    pub seq: i64,
    pub epoch: i64,
}

#[derive(Deserialize)]
pub struct WelcomeElement {
    pub recipient_user: Uuid,
    pub recipient_device: Uuid,
    pub welcome: String,
}

#[derive(Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_device_pair")]
pub struct HintElement {
    pub user_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Deserialize)]
pub struct CommitInput {
    pub epoch: i64,
    pub commit: String,
    pub group_info: String,
    pub welcomes: Vec<WelcomeElement>,
    pub add_hints: Vec<HintElement>,
    pub remove_hints: Vec<HintElement>,
}

#[derive(Deserialize)]
pub struct PrivateMessageInput {
    pub epoch: i64,
    pub ciphertext: String,
}

pub async fn claim_key_pkg(
    _device: DsAccess,
    State(mut state): State<AppState>,
    Json(data): Json<KeyPkgClaimInput>,
) -> Result<Res<Vec<KeyPkgsClaimElementResp>>, InternalError> {
    let user_device_pkgs: Vec<Key_Package> = state
        .pg_interface
        .select_many(Some((&["user_id"], &[data.user_id])),LogicalOp::AND, None)
        .await?;

    let mut key_pkgs: HashMap<Uuid, (Vec<u8>, bool, i64)> = HashMap::new();

    for pkg in user_device_pkgs {
        if let Some(key_pkg) = key_pkgs.get_mut(&pkg.device_id) {
            if key_pkg.1 && !pkg.is_last_resort {
                *key_pkg = (pkg.key_package, pkg.is_last_resort, pkg.id);
            }
        } else {
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

        res.push(KeyPkgsClaimElementResp {
            device_id,
            key_package,
            is_last_resort,
        });
    }

    state
        .pg_interface
        .delete_matches::<i64, Key_Package>(&["id"], &marked_for_deletion, LogicalOp::IN)
        .await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(res),
    });
}

pub async fn create_group(
    device: DsAccess,
    State(mut state): State<AppState>,
    Json(data): Json<NewGroupInput>,
) -> Result<Res<()>, InternalError> {
    let group = state
        .pg_interface
        .insert_one(
            Group {
                id: Uuid::new_v4(),
                epoch: 0,
                groupinfo: B64_ENGINE
                    .decode(data.group_info)
                    .map_err(|_| InternalError::DecodeEncodeErr)?,
                last_seq: 0,
                created_by_user: device.user_id,
                created_by_device: device.device_id,
                created_at: PLACE_HOLDER_TIME,
                updated_at: PLACE_HOLDER_TIME,
            },
            BindVal::ND,
        )
        .await?;

    //TODO: send member hints to mailboxes
    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: None,
    });
}

pub async fn push_proposal(
    _device: DsAccess,
    State(mut state): State<AppState>,
    Path(group_id): Path<Uuid>,
    Json(data): Json<GroupProposalInput>,
) -> Result<Res<SeqEpochResp>, InternalError> {
    let group: Group = state
        .pg_interface
        .select_one((&["id"], &[group_id]), LogicalOp::AND)
        .await?;

    let mut tr = state.pg_interface.begin_transaction().await?;

    let log = tr
        .insert_one(
            Group_Log {
                group_id: group_id,
                seq: group.last_seq + 1,
                epoch: data.epoch,
                kind: LogKind::Proposal,
                payload: B64_ENGINE
                    .decode(data.proposal)
                    .map_err(|_| InternalError::DecodeEncodeErr)?,
                created_at: PLACE_HOLDER_TIME,
            },
            BindVal::ND,
        )
        .await?;

    tr.update_one(Group {
        id: group.id,
        epoch: group.epoch,
        groupinfo: group.groupinfo,
        last_seq: log.seq,
        created_by_user: group.created_by_user,
        created_by_device: group.created_by_device,
        created_at: group.created_at,
        updated_at: group.updated_at,
    })
    .await?;

    tr.commit().await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(SeqEpochResp {
            seq: log.seq,
            epoch: log.epoch,
        }),
    });
}

pub async fn commit_proposals(
    device: DsAccess,
    State(mut state): State<AppState>,
    Path(group_id): Path<Uuid>,
    Json(data): Json<CommitInput>,
) -> Result<Res<SeqEpochResp>, InternalError> {
    let current_group: Group = state
        .pg_interface
        .select_one((&["id"], &[group_id]), LogicalOp::AND)
        .await?;

    if current_group.epoch != data.epoch {
        return Err(InternalError::MismatchedEpoch);
    }

    let mut tr = state.pg_interface.begin_transaction().await?;

    let commit = tr
        .insert_one(
            Group_Log {
                group_id: group_id,
                seq: current_group.last_seq + 1,
                epoch: data.epoch,
                kind: LogKind::Commit,
                payload: B64_ENGINE
                    .decode(data.commit)
                    .map_err(|_| InternalError::DecodeEncodeErr)?,
                created_at: PLACE_HOLDER_TIME,
            },
            BindVal::ND,
        )
        .await?;

    let new_group = tr
        .update_one(Group {
            id: group_id,
            epoch: current_group.epoch + 1,
            groupinfo: B64_ENGINE
                .decode(data.group_info)
                .map_err(|_| InternalError::DecodeEncodeErr)?,
            last_seq: commit.seq,
            created_by_user: current_group.created_by_user,
            created_by_device: current_group.created_by_device,
            created_at: current_group.created_at,
            updated_at: OffsetDateTime::now_utc(),
        })
        .await?;

    let member_removals_query = sqlx::query!(
        r#"DELETE FROM 
        group_member_hints 
        WHERE (user_id, device_id) = ANY($1::user_device_pair[]);"#,
        data.remove_hints as Vec<HintElement>
    );

    let member_inserts: Vec<Group_Member_Hint> = data
        .add_hints
        .into_iter()
        .map(|hint| Group_Member_Hint {
            group_id: group_id,
            user_id: hint.user_id,
            device_id: hint.device_id,
            added_at: PLACE_HOLDER_TIME,
        })
        .collect();

    let mailbox_items: Vec<Mailbox_Item> = data
        .welcomes
        .into_iter()
        .map(|welcome| {
            Ok(Mailbox_Item {
                id: PLACE_HOLDER_UUID,
                ord: 0,
                recipient_user: welcome.recipient_user,
                recipient_device: None,
                kind: MailboxKind::Welcome,
                payload: B64_ENGINE
                    .decode(welcome.welcome)
                    .map_err(|_| InternalError::DecodeEncodeErr)?,
                sender_user: device.user_id,
                sender_device: device.user_id,
                created_at: PLACE_HOLDER_TIME,
            })
        })
        .collect::<Result<Vec<Mailbox_Item>, InternalError>>()?;

    tr.generic_exec(member_removals_query).await?;

    tr.insert_many(&member_inserts, BindVal::ND).await?;
    tr.insert_many(&mailbox_items, BindVal::ND).await?;

    tr.commit().await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(SeqEpochResp {
            seq: new_group.last_seq,
            epoch: new_group.epoch,
        }),
    });
}

pub async fn send_private_message(
    _device: DsAccess,
    State(mut state): State<AppState>,
    Path(group_id): Path<Uuid>,
    Json(data): Json<PrivateMessageInput>,
) -> Result<Res<SeqEpochResp>, InternalError> {
    let current_group: Group = state
        .pg_interface
        .select_one((&["id"], &[group_id]), LogicalOp::AND)
        .await?;

    let mut tr = state.pg_interface.begin_transaction().await?;

    let mut new_group_data = current_group;
    new_group_data.last_seq += 1;
    new_group_data.updated_at = OffsetDateTime::now_utc();

    tr.insert_one(
        Group_Log {
            group_id: group_id,
            seq: new_group_data.last_seq,
            epoch: new_group_data.epoch,
            kind: LogKind::Application,
            payload: B64_ENGINE
                .decode(data.ciphertext)
                .map_err(|_| InternalError::DecodeEncodeErr)?,
            created_at: PLACE_HOLDER_TIME,
        },
        BindVal::ND,
    )
    .await?;

    tr.update_one(new_group_data.clone()).await?;

    tr.commit().await?;

    return Ok(Res {
        status: StatusCode::OK,
        success: true,
        msg: String::new(),
        data: Some(SeqEpochResp {
            seq: new_group_data.last_seq,
            epoch: new_group_data.epoch,
        }),
    });
}
