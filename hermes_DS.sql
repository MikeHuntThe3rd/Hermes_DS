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
    id 			uuid	    PRIMARY KEY,
    epoch               bigint      NOT NULL CHECK (epoch >= 0),
    groupinfo           bytea       NOT NULL CHECK (octet_length(groupinfo) > 0),
    last_seq            bigint      NOT NULL CHECK (last_seq >= 0),
    created_by_user     uuid        NOT NULL,
    created_by_device   uuid        NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX groups_creator ON groups (created_by_user, created_at);

CREATE TABLE group_member_hints (
    group_id    uuid       NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL,
    device_id   uuid        NOT NULL,
    added_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id, device_id)
);

CREATE INDEX group_member_hints_device ON group_member_hints (device_id, group_id);

CREATE TABLE group_logs (
    group_id    uuid       NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    seq         bigint      NOT NULL CHECK (seq >= 1),
    epoch       bigint      NOT NULL CHECK (epoch >= 0),
    kind        log_kind    NOT NULL,
    payload     bytea       NOT NULL CHECK (octet_length(payload) > 0),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, seq)
);

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
    created_at          timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX mailbox_items_user_ord   ON mailbox_items (recipient_user, ord);
CREATE INDEX mailbox_items_device_ord ON mailbox_items (recipient_user, recipient_device, ord)
    WHERE recipient_device IS NOT NULL;
CREATE INDEX mailbox_items_sender     ON mailbox_items (sender_user, created_at);   -- per-sender limit
CREATE INDEX mailbox_items_created_at ON mailbox_items (created_at);                -- retention

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

COMMIT;
