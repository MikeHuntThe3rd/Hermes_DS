BEGIN;

-- -----------------------------------------------------------------------------
-- Types
-- -----------------------------------------------------------------------------

CREATE TYPE user_device_pair AS (user_id uuid, device_id uuid);

-- -----------------------------------------------------------------------------
-- Enums
-- -----------------------------------------------------------------------------

CREATE TYPE log_kind AS ENUM ('commit', 'proposal', 'application');

CREATE TYPE mailbox_kind AS ENUM (
    'welcome', 'friend_request', 'friend_response',
    'invite_accept', 'invite_decline', 'device_link', 'other'
);

CREATE TYPE blob_status AS ENUM ('pending', 'available');

-- -----------------------------------------------------------------------------
-- Tables
-- -----------------------------------------------------------------------------

CREATE TABLE key_packages (
    id              bigserial 	PRIMARY KEY,
    user_id         uuid        NOT NULL,
    device_id       uuid        NOT NULL,
    key_package     bytea       NOT NULL CHECK (octet_length(key_package) > 0),
    is_last_resort  boolean     NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX key_packages_one_last_resort
    ON key_packages (user_id, device_id)
    WHERE is_last_resort;

CREATE UNIQUE INDEX key_packages_no_dupes
    ON key_packages (device_id, md5(key_package))
    WHERE NOT is_last_resort;

CREATE INDEX key_packages_claim
    ON key_packages (user_id, device_id, id)
    WHERE NOT is_last_resort;

CREATE TABLE groups (
    id                  uuid        PRIMARY KEY,
    latest_seq          bigint      NOT NULL DEFAULT 0 CHECK (latest_seq >= 0),
    created_by_user     uuid        NOT NULL,
    created_by_device   uuid        NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX groups_creator ON groups (created_by_user, created_at);

CREATE TABLE group_infos (
    group_id            uuid        NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    seq                 bigint      NOT NULL CHECK (seq >= 0),
    epoch               bigint      NOT NULL CHECK (epoch >= 0),     -- the epoch this GroupInfo describes (commit epoch + 1)
    groupinfo           bytea       NOT NULL CHECK (octet_length(groupinfo) > 0),
    submitted_by_user   uuid        NOT NULL,                        -- stamped by the DS from the token
    submitted_by_device uuid        NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, seq)
);

CREATE INDEX group_infos_epoch ON group_infos (group_id, epoch);

CREATE TABLE group_member_hints (
    group_id    uuid       NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL,
    device_id   uuid        NOT NULL,
    added_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id, device_id)
);

CREATE INDEX group_member_hints_device ON group_member_hints (device_id, group_id);

CREATE TABLE group_logs (
    id                  bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    group_id            uuid        NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    seq                 bigint      NOT NULL CHECK (seq >= 1),
    epoch               bigint      NOT NULL CHECK (epoch >= 0),
    kind                log_kind    NOT NULL,
    payload             bytea       NOT NULL CHECK (octet_length(payload) > 0),
    submitted_by_user   uuid        NOT NULL,                        -- stamped by the DS from the token
    submitted_by_device uuid        NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (group_id, seq)
);

CREATE INDEX group_logs_epoch     ON group_logs (group_id, epoch, seq);
CREATE INDEX group_logs_submitter ON group_logs (group_id, submitted_by_device, created_at);   -- per-device quota
CREATE INDEX group_log_created_at ON group_logs (created_at);

CREATE TABLE mailbox_items (
    id                  uuid         PRIMARY KEY DEFAULT uuidv4(),
    ord                 bigserial    NOT NULL,
    recipient_user      uuid         NOT NULL,
    recipient_device    uuid,
    kind                mailbox_kind NOT NULL,
    payload             bytea        NOT NULL CHECK (octet_length(payload) > 0),
    sender_user         uuid         NOT NULL,
    sender_device       uuid         NOT NULL,
    commit_id           bigint       REFERENCES group_logs (id) ON DELETE CASCADE,
    created_at          timestamptz  NOT NULL DEFAULT now(),
    CHECK ((kind = 'welcome') = (commit_id IS NOT NULL))
);

CREATE INDEX mailbox_items_user_ord   ON mailbox_items (recipient_user, ord);
CREATE INDEX mailbox_items_device_ord ON mailbox_items (recipient_user, recipient_device, ord)
    WHERE recipient_device IS NOT NULL;
CREATE INDEX mailbox_items_sender     ON mailbox_items (sender_user, created_at);   -- per-sender limit
CREATE INDEX mailbox_items_created_at ON mailbox_items (created_at);                -- retention
CREATE INDEX mailbox_items_commit     ON mailbox_items (commit_id)                  -- FK cascade
    WHERE commit_id IS NOT NULL;

CREATE TABLE mailbox_acks (
    item_id     uuid        NOT NULL REFERENCES mailbox_items (id) ON DELETE CASCADE,
    device_id   uuid        NOT NULL,
    acked_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (item_id, device_id)
);

CREATE TABLE blobs (
    id                  uuid        PRIMARY KEY DEFAULT uuidv4(),
    owner_user          uuid        NOT NULL,
    owner_device        uuid        NOT NULL,
    size_bytes          bigint      NOT NULL CHECK (size_bytes > 0),
    checksum_sha256     bytea       CHECK (checksum_sha256 IS NULL OR octet_length(checksum_sha256) = 32),
    completed_at        timestamptz,
    expires_at          timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    status              blob_status NOT NULL DEFAULT 'pending',
    CHECK ((status = 'available') = (completed_at IS NOT NULL))
);

CREATE INDEX blobs_owner_quota ON blobs (owner_user) INCLUDE (size_bytes);
CREATE INDEX blobs_pending_expiry ON blobs (expires_at) WHERE status = 'pending';
CREATE INDEX blobs_available_age ON blobs (created_at) WHERE status = 'available';

-- -----------------------------------------------------------------------------
-- Reference statements (not executed here)
-- -----------------------------------------------------------------------------
-- Create group:   INSERT INTO groups (id, created_by_user, created_by_device) VALUES (...);
--                 INSERT INTO group_infos (group_id, seq, epoch, groupinfo, submitted_by_user, submitted_by_device)
--                      VALUES ($1, 0, 0, $2, $user, $device);
--
-- Append any entry (one transaction; the UPDATE takes the group row lock, so seq is gapless):
--   UPDATE groups SET latest_seq = latest_seq + 1 WHERE id = $1
--   RETURNING latest_seq;                                                     -- 0 rows => unknown group
--   -- commit:
--   INSERT INTO group_logs (group_id, seq, epoch, kind, payload, submitted_by_user, submitted_by_device)
--        VALUES ($1, <latest_seq>, $epoch, 'commit', $commit, $user, $device)   -- starting epoch
--   RETURNING id;                                                             -- <commit_id>
--   INSERT INTO group_infos (group_id, seq, epoch, groupinfo, submitted_by_user, submitted_by_device)
--        VALUES ($1, <latest_seq>, $epoch + 1, $groupinfo, $user, $device);
--   INSERT INTO mailbox_items (recipient_user, recipient_device, kind, payload,
--                              sender_user, sender_device, commit_id)
--        VALUES (..., 'welcome', $welcome, $user, $device, <commit_id>);      -- one per welcome
--   then apply the group_member_hints adds and removes.
--   -- proposal / application message: only the group_logs insert, with kind 'proposal' / 'application'.
-- No epoch bound is enforced. If one is ever wanted it can be derived:
--   SELECT max(epoch) FROM group_infos WHERE group_id = $1;   -- served by group_infos_epoch
--
-- Quota check before the UPDATE (so rejected requests do not take the group lock):
--   SELECT count(*) FROM group_logs
--    WHERE group_id = $1 AND submitted_by_device = $device AND created_at > now() - $window;
--
-- Mailbox read, with the commit link the API shows:
--   SELECT i.*, l.group_id, l.seq AS commit_seq
--     FROM mailbox_items i LEFT JOIN group_logs l ON l.id = i.commit_id ...

COMMIT;
