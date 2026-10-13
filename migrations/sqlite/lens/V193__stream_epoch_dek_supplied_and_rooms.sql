-- V193 — a stream epoch's DEK may be caller-supplied (always kept), and a
-- room's stream is stream-keyed too. SQLite dialect.
-- v55.0.0 (CIRISPersist#981, #977; CC 5.3.3.1, CC 5.1, CC 5.3.3.2.5).
--
-- POSTGRES PARITY: migrations/postgres/lens/V193__stream_epoch_dek_supplied_and_rooms.sql
--
-- WHY
-- ---
-- 1. #977 — CC 5.1 keys an N>1 stream per (stream_id, epoch) and carries the
--    epoch DEK on the flat key_grant cascade; a community chunk DAG was sealed
--    under the community epoch DEK with a random nonce. v55 moves a room's
--    stream onto the V168 stream-epoch DEK (the STREAM nonce, a terminator per
--    epoch, `key_grant:stream:v1` rows at the room's scope). V168 constrained
--    `cohort_scope` to self / family on both tables; it now admits the two
--    room scopes.
--    A room stream epoch records `room_epoch`, the writer's community epoch
--    at its mint, so the community retention sweep evicts its chunks under
--    the same `retain_past_epochs` policy as the community epoch's own
--    objects (operator ruling: a room's retention bound covers every byte
--    sealed for that room).
-- 2. #981 — a live call's DEK is the per-(stream, epoch) DEK its producer
--    derives from the group's MLS exporter (CC 5.1; rc8 ruling). The caller SUPPLIES
--    the (stream_id, epoch) DEK (`supplied`); a supplied epoch is always kept
--    and wrapped to the audience. An unrecorded live call never reaches
--    persist: CC rc7 part 5 ("An unrecorded live call wraps nothing") forbids
--    any durable wrap of its DEK, and a stored DEK row is one.
--    Persist never mints or rolls a supplied stream's epoch: a removal or the
--    nonce cap is the typed retryable `stream_epoch_rotation_required`.
--
-- HOW
-- ---
-- SQLite cannot widen a CHECK in place, so both tables are rebuilt: staged,
-- dropped, and re-created UNDER THEIR FINAL NAMES (no `_new` + RENAME: the
-- V136 lesson). Neither table is the target or the source of a foreign key.
-- Every existing row is a persist-minted epoch: `supplied = 0`.
CREATE TABLE _v193_stage_stream_deks AS
    SELECT stream_id, epoch, owner_key_id, cohort_scope, group_key_id,
           self_retention_wrap, minted_at, closed_at, terminated_at,
           key_grant_emitted_at
    FROM federation_stream_deks;

CREATE TABLE _v193_stage_stream_dek_grants AS
    SELECT stream_id, epoch, sealer_key_id, recipient_key_id, wrap_algorithm,
           wrapped_dek, cohort_scope, created_at
    FROM federation_stream_dek_grants;

DROP INDEX IF EXISTS federation_stream_dek_grants_recipient;
DROP TABLE federation_stream_dek_grants;
DROP TABLE federation_stream_deks;

CREATE TABLE federation_stream_deks (
    stream_id             TEXT NOT NULL,
    epoch                 INTEGER NOT NULL CHECK (epoch >= 0),
    owner_key_id          TEXT NOT NULL,
    cohort_scope          TEXT NOT NULL
        CHECK (cohort_scope IN ('self', 'family', 'community', 'affiliations')),
    group_key_id          TEXT NOT NULL,
    self_retention_wrap   TEXT NOT NULL,
    minted_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    closed_at             TEXT,
    terminated_at         TEXT,
    key_grant_emitted_at  TEXT,
    -- #981 — the caller supplied this epoch's DEK (persist never rolls it).
    supplied              INTEGER NOT NULL DEFAULT 0 CHECK (supplied IN (0, 1)),
    -- #977 — a room stream epoch's place in the room's retention: the
    -- writer's community epoch when the stream epoch was minted. The
    -- community retention sweep evicts the epoch's chunks under the same
    -- policy as the community epoch it names; NULL for self / family.
    room_epoch            INTEGER CHECK (room_epoch IS NULL OR room_epoch >= 0),
    -- #977 — when that sweep evicted the epoch's chunks (the row stays).
    evicted_at            TEXT,
    PRIMARY KEY (stream_id, epoch)
);

CREATE TABLE federation_stream_dek_grants (
    stream_id         TEXT NOT NULL,
    epoch             INTEGER NOT NULL CHECK (epoch >= 0),
    sealer_key_id     TEXT NOT NULL,
    recipient_key_id  TEXT NOT NULL,
    wrap_algorithm    TEXT NOT NULL
        CHECK (wrap_algorithm IN ('x25519_mlkem768_aes256_gcm_hkdf_sha256')),
    wrapped_dek       TEXT NOT NULL,
    cohort_scope      TEXT NOT NULL
        CHECK (cohort_scope IN ('self', 'family', 'community', 'affiliations')),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    PRIMARY KEY (stream_id, epoch, sealer_key_id, recipient_key_id)
);

CREATE INDEX IF NOT EXISTS federation_stream_dek_grants_recipient
    ON federation_stream_dek_grants (recipient_key_id, cohort_scope);

INSERT INTO federation_stream_deks
    (stream_id, epoch, owner_key_id, cohort_scope, group_key_id,
     self_retention_wrap, minted_at, closed_at, terminated_at,
     key_grant_emitted_at, supplied)
SELECT stream_id, epoch, owner_key_id, cohort_scope, group_key_id,
       self_retention_wrap, minted_at, closed_at, terminated_at,
       key_grant_emitted_at, 0
FROM _v193_stage_stream_deks;

INSERT INTO federation_stream_dek_grants
    (stream_id, epoch, sealer_key_id, recipient_key_id, wrap_algorithm,
     wrapped_dek, cohort_scope, created_at)
SELECT stream_id, epoch, sealer_key_id, recipient_key_id, wrap_algorithm,
       wrapped_dek, cohort_scope, created_at
FROM _v193_stage_stream_dek_grants;

DROP TABLE _v193_stage_stream_dek_grants;
DROP TABLE _v193_stage_stream_deks;
