-- V210 — admit `open:self_admit` into federation_communities.consensus_protocol.
-- SQLite dialect. v61 (CIRISPersist#1123; CC 4.4.3.2, 4.4.3.4.2, 4.5.13).
--
-- POSTGRES PARITY: migrations/postgres/lens/V210__consensus_protocol_open_self_admit.sql
-- (see it for WHY: a `public` room's open admission is its protocol,
-- `open:self_admit`, and the V116/V141 CHECK does not admit the string).
--
-- HOW (the staged rebuild, never `_new` + RENAME)
-- ------------------------------------------------
-- SQLite bakes the CHECK into CREATE TABLE, so the table is rebuilt. Two
-- tables REFERENCE it (V151): `federation_community_membership_revocations`
-- and `federation_community_membership_widenings` (V156's listing table was
-- dropped by V209). Nothing references those two. The `_new` + RENAME shape
-- leaves SQLite's deferred-FK counter +1 for a table with referrers, and the
-- COMMIT is refused with `foreign_key_check` clean (the V136 finding), so:
-- stage the table and both referrers, empty the referrers, drop the table,
-- re-create it under its FINAL name, and restore the rows parents first. The
-- referrers spell the parent's name textually and rebind to the new table.
--
-- The column list is the table as V206 left it (V141's rebuild + V155
-- `supersede_proof`, V158 `cosignatures` / `lineage`, V174 `prev_head_digest`
-- / `charter_digest`, V206 `attestation_id`), in its order, with its types,
-- NULL-ability, defaults and its FK to `federation_attestations`. The whole
-- diff of the CHECK is the added `open:self_admit` arm. The three indexes are
-- re-created as V141 / V206 declared them.

PRAGMA defer_foreign_keys = ON;

CREATE TABLE _v210_stage_communities AS
    SELECT community_key_id, community_name, members, founded_at,
           consensus_protocol, policy_blob, persist_row_hash, version,
           authority_key_id, scrub_signature_classical, scrub_signature_pqc,
           admitted_at, supersede_proof, cosignatures, lineage,
           prev_head_digest, charter_digest, attestation_id
    FROM federation_communities;

CREATE TABLE _v210_stage_revocations AS
    SELECT * FROM federation_community_membership_revocations;

CREATE TABLE _v210_stage_widenings AS
    SELECT * FROM federation_community_membership_widenings;

DELETE FROM federation_community_membership_revocations;
DELETE FROM federation_community_membership_widenings;

DROP TABLE federation_communities;

CREATE TABLE federation_communities (
    community_key_id      TEXT PRIMARY KEY,
    community_name        TEXT NOT NULL,
    members               TEXT NOT NULL,
    founded_at            TEXT NOT NULL,
    consensus_protocol    TEXT NOT NULL,
    policy_blob           TEXT,
    persist_row_hash      TEXT NOT NULL,
    version               INTEGER NOT NULL DEFAULT 1,
    authority_key_id           TEXT,
    scrub_signature_classical  TEXT,
    scrub_signature_pqc        TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at                TEXT NOT NULL,
    supersede_proof            TEXT,
    cosignatures               TEXT NOT NULL DEFAULT '[]',
    lineage                    TEXT NOT NULL DEFAULT '[]',
    prev_head_digest           TEXT NOT NULL DEFAULT '',
    charter_digest             TEXT NOT NULL DEFAULT '',
    attestation_id             TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL,
    CHECK (consensus_protocol GLOB 'founder_only'
        OR consensus_protocol GLOB 'unanimous'
        OR consensus_protocol GLOB 'majority'
        -- v61 (CIRISPersist#1123) — a public room's open admission.
        OR consensus_protocol = 'open:self_admit'
        OR consensus_protocol GLOB 'quorum:*/*'
        OR consensus_protocol GLOB 'reverse_quorum:*/*:*'
        OR consensus_protocol GLOB 'weighted:?*'
        OR consensus_protocol GLOB 'custom:?*')
);

INSERT INTO federation_communities (
    community_key_id, community_name, members, founded_at, consensus_protocol,
    policy_blob, persist_row_hash, version, authority_key_id,
    scrub_signature_classical, scrub_signature_pqc, admitted_at,
    supersede_proof, cosignatures, lineage, prev_head_digest, charter_digest,
    attestation_id)
SELECT
    community_key_id, community_name, members, founded_at, consensus_protocol,
    policy_blob, persist_row_hash, version, authority_key_id,
    scrub_signature_classical, scrub_signature_pqc, admitted_at,
    supersede_proof, cosignatures, lineage, prev_head_digest, charter_digest,
    attestation_id
FROM _v210_stage_communities;

INSERT INTO federation_community_membership_revocations
    SELECT * FROM _v210_stage_revocations;

INSERT INTO federation_community_membership_widenings
    SELECT * FROM _v210_stage_widenings;

DROP TABLE _v210_stage_communities;
DROP TABLE _v210_stage_revocations;
DROP TABLE _v210_stage_widenings;

CREATE INDEX federation_communities_admitted
    ON federation_communities (COALESCE(admitted_at, founded_at), community_key_id);

CREATE UNIQUE INDEX federation_communities_by_attestation
    ON federation_communities (attestation_id);

CREATE INDEX federation_communities_without_row
    ON federation_communities (community_key_id) WHERE attestation_id IS NULL;
