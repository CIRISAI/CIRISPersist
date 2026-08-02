-- V116 — admit the OBJECTION form into federation_communities.consensus_protocol,
-- SQLite dialect
-- v24.3.0 (CIRISPersist#574)
--
-- POSTGRES PARITY: migrations/postgres/lens/V116__consensus_protocol_reverse_quorum.sql
-- (same form admitted there; Postgres has DROP CONSTRAINT so its twin is a
-- discovery-drop plus a re-add, and this one is a table rebuild. See that file
-- for the FULL rationale — why the commons needs an act-unless-objected form
-- at all, and why the vocabulary is closed in three places rather than one.)
--
-- THE SHORT VERSION
-- -----------------
-- V060's six forms are all APPROVE-TO-ACT: each names who must sign BEFORE an
-- action lands. That governs the group correctly and polices the commons not
-- at all — a community's only responses to a harmful federation-scoped row
-- were one member acting unilaterally (illegitimate) or a quorum assembling
-- first (too slow). V116 adds the third:
--
--     reverse_quorum:{m}/{n}:{window_secs}       e.g. reverse_quorum:2/5:86400
--
-- The action lands on arrival; any ONE current member may object; `m` distinct
-- in-window objectors reverse it; dismissing an objection costs m-of-n floored
-- at a strict majority. 1-of-N to protect, m-of-n to undo.
--
-- Nothing is removed and no row changes: the six existing forms remain
-- admissible with identical meaning.
--
-- `federation_families.consensus_protocol` carries NO CHECK (V059 left it
-- unconstrained and V097's rebuild preserved that), so there is deliberately
-- nothing to widen there.
--
-- HOW (the SQLite table-rebuild recipe)
-- -------------------------------------
-- SQLite bakes table-level CHECKs into CREATE TABLE and has no
-- `ALTER TABLE ... DROP CONSTRAINT`, so the table is rebuilt (the V020 / V035 /
-- V061 / V097 / V114 / V115 recipe). `federation_communities` is the easy case:
--   * NOTHING references it — verified across the whole migration set: no
--     `REFERENCES federation_communities` anywhere, and the membership /
--     revocation / DEK tables key on `community_key_id` as a free-form column
--     with no FK. So the DROP fires no cascade and nothing needs staging;
--   * it carries no triggers and NO INDEXES (the sqlite read path scans via
--     `json_each` — the postgres `@>` GIN index is that backend's
--     optimization, so there is no index to recreate here);
--   * its column set is V060 (7 columns) + V089 (`version`) + V110 (the three
--     E4 authority-signature columns), all reproduced below with their
--     original types, NULL-ability and defaults.
--
-- The ONE constraint on this table is the one being widened, so there is no
-- other CHECK to transcribe — a rebuild is the moment a constraint can be
-- silently lost or narrowed by transcription, and here the whole diff is the
-- added `reverse_quorum:*/*:*` arm.
--
-- VERIFIED BY HAND against a populated table, because the suite cannot: every
-- test database runs its migrations before any row exists, so the
-- INSERT…SELECT above is never exercised with data by CI. Driven manually on a
-- post-V115 schema holding a `quorum:2/3` community with all eleven columns
-- populated: the row survives byte-for-byte, the PRIMARY KEY survives, the six
-- legacy forms stay admissible, and malformed `reverse_quorum:` strings are
-- still refused. A rebuild that silently dropped rows would pass CI.
--
-- `PRAGMA` statements are no-ops inside refinery's per-migration transaction,
-- which is fine — with no inbound FKs there is nothing to defer.
--
-- NOTE on GLOB vs the postgres regex: GLOB has no `[0-9]+`, so the sqlite arm
-- is the same shape check at coarser resolution (`reverse_quorum:*/*:*`),
-- exactly as V060's `quorum:*/*` is coarser than the postgres
-- `quorum:[0-9]+/[0-9]+`. The precise parse — digits only, `0 < m <= n`, a
-- window that reads as seconds — is `ReverseQuorumPolicy::parse`, the single
-- parser both the Rust shape gate and the fold run, so the strictness lives in
-- one place on both backends rather than being approximated twice.

CREATE TABLE federation_communities_new (
    community_key_id      TEXT PRIMARY KEY,
    community_name        TEXT NOT NULL,
    members               TEXT NOT NULL,   -- JSON-shaped
    founded_at            TEXT NOT NULL,   -- RFC-3339
    consensus_protocol    TEXT NOT NULL,
    policy_blob           TEXT,            -- JSON-shaped or NULL
    persist_row_hash      TEXT NOT NULL,
    -- V089
    version               INTEGER NOT NULL DEFAULT 1,
    -- V110 (E4 authority signatures)
    authority_key_id           TEXT,
    scrub_signature_classical  TEXT,
    scrub_signature_pqc        TEXT,
    CHECK (consensus_protocol GLOB 'founder_only'
        OR consensus_protocol GLOB 'unanimous'
        OR consensus_protocol GLOB 'majority'
        OR consensus_protocol GLOB 'quorum:*/*'
        -- v24.3.0 (CIRISPersist#574) — the objection form joins the set.
        OR consensus_protocol GLOB 'reverse_quorum:*/*:*'
        OR consensus_protocol GLOB 'weighted:?*'
        OR consensus_protocol GLOB 'custom:?*')
);

INSERT INTO federation_communities_new (
    community_key_id, community_name, members, founded_at, consensus_protocol,
    policy_blob, persist_row_hash, version, authority_key_id,
    scrub_signature_classical, scrub_signature_pqc)
SELECT
    community_key_id, community_name, members, founded_at, consensus_protocol,
    policy_blob, persist_row_hash, version, authority_key_id,
    scrub_signature_classical, scrub_signature_pqc
FROM federation_communities;

DROP TABLE federation_communities;

ALTER TABLE federation_communities_new RENAME TO federation_communities;
