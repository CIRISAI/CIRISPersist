-- V145 — an epoch belongs to its MINTER: `minter_key_id` on every community-DEK
-- key-state table, SQLite dialect
-- v44.3.0 (CIRISPersist#848, FSD/BLOB_REPLICATION.md §11, §16)
--
-- POSTGRES PARITY: migrations/postgres/lens/V145__per_minter_dek_epochs.sql
-- (postgres can ADD COLUMN, backfill and swap a PRIMARY KEY in place; this
-- dialect cannot change a primary key, so four tables are rebuilt.)
--
-- WHY
-- ---
-- `federation_community_dek` was keyed `(community, epoch)`, `ensure_epoch_dek`
-- minted from the LOCAL self-retention row, and the epoch pointer was bumped
-- only on the revoking node. Two members writing at the same epoch number
-- minted two random DEKs both labelled E, and the member-grant table could
-- hold one of them. The Constitution rules `(community, epoch)` with no lease
-- and no per-delegate fold an undeclared serialization discipline — a FORK by
-- definition (ledger clause 3; CC 5.3.3 for streams). The ruling (#848) is
-- per-minter epochs: an epoch belongs to the occurrence whose cascade minted
-- it, so key state, self-retention and grants are keyed
-- `(community_key_id, minter_key_id, epoch)`, and a blob's key identity is
-- `(community, author, epoch)` — the author is already on the row (V144).
--
-- THE SENTINEL, AND WHY ONLY THE RUNNING NODE CAN RESOLVE IT
-- ----------------------------------------------------------
-- The backfill is exact: every existing key-state row on a node was minted by
-- that node (before #848 nothing carried a wrap between nodes). But SQL cannot
-- know the node's derived federation key — it lives in the signer. So this
-- migration writes the sentinel `__this_node__`, and a boot-time step beside
-- the #840 / #845 repairs (`SqliteBackend::repair_minter_sentinel`, run from
-- the Engine's construction path the moment the signer and the backend exist
-- together, BEFORE any read) resolves it to the node's own key. A sentinel
-- that survives that step ABORTS THE BOOT: a minter of nobody would be a key
-- nobody can be asked for.
--
-- The blob binding follows the DEK it was sealed under, never the row's author
-- on its own: a binding whose (community, epoch) has a local DEK row was
-- minted HERE — pre-V145 every local DEK was this node's, whatever key the row
-- names as author (a node whose signer rotated since the write would otherwise
-- bind old content to a minter that holds no DEK, and lose it) — so it takes
-- the sentinel with the DEK rows it belongs to. A binding with NO local DEK
-- row was adopted (#846: the bytes arrived, the key never did) and names its
-- author, who IS the minter; an adopted row with a NULL author takes the
-- sentinel too (nothing better is known). PR #850 review, round three.
--
-- HOW (the V136 rebuild shape)
-- ----------------------------
-- Stage every row, DROP the table, re-create it UNDER ITS FINAL NAME, restore
-- from the stage, recreate the indexes verbatim. No `_new` table and no
-- RENAME — V136's header records why that shape breaks on a self-FK; none of
-- these four tables carries one and nothing references them by FK (checked:
-- no `REFERENCES federation_community_*` exists in any migration), so the
-- rebuild is inert under `PRAGMA foreign_keys = ON`. The pragma is kept as
-- belt-and-braces, as V136 and V141 keep it.
--
-- Every CHECK, default and NULL-ability is reproduced from V087 / V138 / V139
-- / V140, with two deliberate changes beyond the key: `minted_at` on
-- `federation_community_dek` (§15 — the instant a removal is compared against;
-- backfilled from `created_at`, which IS that instant on every existing row),
-- and the timestamp defaults spelled in the portable form
-- `strftime('%Y-%m-%d %H:%M:%f', 'now')` that #845 rewrites the older files
-- to at boot (a new migration must not reintroduce the modifier — I56).
--
-- Every stage SELECT and restore INSERT spells its columns: a migration runs
-- against one frozen schema (the V144 shape), so an explicit list is exact and
-- auditable in a way `*` is not.

PRAGMA defer_foreign_keys = ON;

-- ── 1. stage ─────────────────────────────────────────────────────────────
CREATE TABLE _v145_stage_epoch AS
    SELECT community_key_id, epoch, rotated_at, retain_past_epochs
    FROM federation_community_dek_epoch;

CREATE TABLE _v145_stage_dek AS
    SELECT community_key_id, epoch, wrap_algorithm, wrapped_dek, created_at, key_state
    FROM federation_community_dek;

CREATE TABLE _v145_stage_grants AS
    SELECT community_key_id, epoch, member_key_id, wrap_algorithm, wrapped_dek, created_at
    FROM federation_community_dek_member_grants;

CREATE TABLE _v145_stage_blob_epoch AS
    SELECT at_rest_sha256, community_key_id, epoch, created_at, evicted_at
    FROM federation_community_blob_epoch;

-- ── 2. drop, then re-create UNDER THE FINAL NAME ─────────────────────────
DROP TABLE federation_community_dek_epoch;
DROP TABLE federation_community_dek;
DROP TABLE federation_community_dek_member_grants;
DROP TABLE federation_community_blob_epoch;

-- The current sealing epoch, PER MINTER. On this node the only minter with a
-- pointer row is this node itself (a foreign minter's counter is its own to
-- advance; this node only ever holds its grants, §13).
CREATE TABLE federation_community_dek_epoch (
    community_key_id    TEXT NOT NULL,
    minter_key_id       TEXT NOT NULL,
    epoch               INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    rotated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    retain_past_epochs  INTEGER
        CHECK (retain_past_epochs IS NULL OR retain_past_epochs >= 0),
    PRIMARY KEY (community_key_id, minter_key_id)
);

-- Persist's self-retention wrap of the `(community, minter, epoch)` DEK, and
-- its key state. Only this node's own mints have a row here (the wrap is
-- under THIS node's content master); a peer's epoch is known through the
-- member-grant table alone.
CREATE TABLE federation_community_dek (
    community_key_id  TEXT NOT NULL,
    minter_key_id     TEXT NOT NULL,
    epoch             INTEGER NOT NULL CHECK (epoch >= 0),
    wrap_algorithm    TEXT NOT NULL
        CHECK (wrap_algorithm IN ('aes256_gcm_content_master')),
    -- NULL iff key_state = 'destroyed': the material is gone (V139).
    wrapped_dek       TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    -- §15 — when THIS minter minted the DEK. A removal admitted after this
    -- instant rotates the minter's counter before its next seal.
    minted_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    key_state         TEXT NOT NULL DEFAULT 'enabled'
        CHECK (key_state IN ('enabled', 'disabled', 'destroyed')),
    CHECK ((key_state = 'destroyed') = (wrapped_dek IS NULL)),
    PRIMARY KEY (community_key_id, minter_key_id, epoch)
);

-- One v2 wrap per `(community, minter, epoch, recipient occurrence)` — this
-- node's own fan-out AND every admitted `KeyGrant` set (§13: a union, never
-- reduced by a later set).
CREATE TABLE federation_community_dek_member_grants (
    community_key_id      TEXT NOT NULL,
    minter_key_id         TEXT NOT NULL,
    epoch                 INTEGER NOT NULL CHECK (epoch >= 0),
    member_key_id         TEXT NOT NULL,
    wrap_algorithm        TEXT NOT NULL
        CHECK (wrap_algorithm IN ('x25519_mlkem768_aes256_gcm_hkdf_sha256')),
    wrapped_dek           TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    PRIMARY KEY (community_key_id, minter_key_id, epoch, member_key_id)
);

-- Which `(community, minter, epoch)` DEK sealed a blob. `evicted_at` (V140)
-- is the retention sweep's stamp; NULL = the blob row exists.
CREATE TABLE federation_community_blob_epoch (
    at_rest_sha256    BLOB PRIMARY KEY
        CHECK (length(at_rest_sha256) = 32),
    community_key_id  TEXT NOT NULL,
    minter_key_id     TEXT NOT NULL,
    epoch             INTEGER NOT NULL CHECK (epoch >= 0),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    evicted_at        TEXT
);

-- ── 3. restore, with the sentinel where SQL cannot know the minter ───────
INSERT INTO federation_community_dek_epoch
    (community_key_id, minter_key_id, epoch, rotated_at, retain_past_epochs)
SELECT community_key_id, '__this_node__', epoch, rotated_at, retain_past_epochs
FROM _v145_stage_epoch;

INSERT INTO federation_community_dek
    (community_key_id, minter_key_id, epoch, wrap_algorithm, wrapped_dek,
     created_at, minted_at, key_state)
SELECT community_key_id, '__this_node__', epoch, wrap_algorithm, wrapped_dek,
       created_at, created_at, key_state
FROM _v145_stage_dek;

INSERT INTO federation_community_dek_member_grants
    (community_key_id, minter_key_id, epoch, member_key_id, wrap_algorithm,
     wrapped_dek, created_at)
SELECT community_key_id, '__this_node__', epoch, member_key_id, wrap_algorithm,
       wrapped_dek, created_at
FROM _v145_stage_grants;

-- The binding's minter is the blob's author where the row says who that is
-- (V144); the sentinel only where the row predates the column.
INSERT INTO federation_community_blob_epoch
    (at_rest_sha256, community_key_id, minter_key_id, epoch, created_at, evicted_at)
SELECT s.at_rest_sha256,
       s.community_key_id,
       CASE
           WHEN EXISTS (SELECT 1 FROM federation_community_dek d
                         WHERE d.community_key_id = s.community_key_id
                           AND d.epoch = s.epoch)
           THEN '__this_node__'
           ELSE COALESCE((SELECT b.author_key_id FROM federation_blobs b
                           WHERE b.sha256 = s.at_rest_sha256), '__this_node__')
       END,
       s.epoch,
       s.created_at,
       s.evicted_at
FROM _v145_stage_blob_epoch s;

DROP TABLE _v145_stage_epoch;
DROP TABLE _v145_stage_dek;
DROP TABLE _v145_stage_grants;
DROP TABLE _v145_stage_blob_epoch;

-- ── 4. indexes ───────────────────────────────────────────────────────────
-- V087's by-member seek, verbatim.
CREATE INDEX IF NOT EXISTS federation_community_dek_member_grants_by_member
    ON federation_community_dek_member_grants (member_key_id);

-- V138's reverse seek — the DESTROY precondition and the sweep — now keyed
-- on the full epoch identity.
CREATE INDEX IF NOT EXISTS federation_community_blob_epoch_by_community_epoch
    ON federation_community_blob_epoch (community_key_id, minter_key_id, epoch);
