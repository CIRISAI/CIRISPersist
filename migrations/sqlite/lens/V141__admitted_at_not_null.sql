-- V141 — `admitted_at` is NOT NULL on sqlite, as it has been on postgres since V130
-- (CIRISPersist#828)
--
-- POSTGRES PARITY: migrations/postgres/lens/V141__admitted_at_not_null.sql
-- (a no-op there: postgres backfilled and `SET NOT NULL` in V123 / V126 / V130.
-- The twin exists so both trees carry the same version for the same change.)
--
-- WHAT AND WHY
-- ------------
-- `admitted_at` is THIS node's receiver-stamped admission instant — the serve
-- position every `list_*_since` cursor pages on. V123 (revocations), V126
-- (keys) and V130 (the other twelve) added it. Postgres backfilled and then
-- `ALTER COLUMN ... SET NOT NULL`. SQLite's `ALTER TABLE ADD COLUMN` cannot
-- declare NOT NULL without a constant default, a receiver-stamped instant has
-- no meaningful constant default, and sqlite cannot alter nullability in
-- place — so on this dialect the column was added nullable and LEFT nullable,
-- with the Rust write doors as the only enforcement point.
--
-- That divergence was invisible for thirteen versions because the
-- schema-parity replayer (`store::schema_parity`) could not read
-- `SET NOT NULL`, believed both dialects nullable, and reported agreement.
-- v43.0.0 taught it, the fourteen findings appeared at once, and were
-- DECLARED in `NULLABILITY_DIVERGENCES` rather than fixed. This migration is
-- the fix; the fourteen declarations are deleted in the same cut, and the
-- gate `nullability_agrees_across_the_two_trees` is what proves no table was
-- missed.
--
-- Exposure before this: every persist write door stamps `admitted_at`, so no
-- persist API admitted a NULL on either backend. A raw writer bypassing the
-- doors could on sqlite; on postgres it was refused. After this, both refuse.
--
-- BACKFILL — the source per table, spelled out
-- --------------------------------------------
-- Any row still NULL is stamped with the instant its cursor ordered by before
-- the column existed — exactly the expression V123 / V126 / V130 used, so a
-- row this migration touches sorts where it always did and no consumer's
-- saved cursor goes backward. (Every write door has stamped the column since
-- those versions, so on a database that only ever wrote through persist this
-- is a no-op; it exists for the raw-writer case, and because a rebuild that
-- ASSUMES its input is clean fails at the restore INSERT with a NOT NULL
-- refusal and no row named.)
--
--   federation_attestations                      COALESCE(promoted_at, asserted_at)   (V130)
--   federation_communities                       founded_at                           (V130)
--   federation_community_membership_revocations  removed_at                           (V130)
--   federation_families                          founded_at                           (V130)
--   federation_family_membership_revocations     removed_at                           (V130)
--   federation_identity_occurrence_revocations   revoked_at                           (V130)
--   federation_identity_occurrences              asserted_at                          (V130)
--   federation_keys                              scrub_timestamp                      (V126)
--   federation_location_proofs                   asserted_at                          (V130)
--   federation_organizations                     asserted_at                          (V130)
--   federation_org_memberships                   asserted_at                          (V130)
--   federation_partner_records                   asserted_at                          (V130)
--   federation_revocations                       scrub_timestamp                      (V123)
--   transport_destinations                       asserted_at                          (V130)
--
-- HOW — the V136 recipe, and why it is the ONLY safe one here
-- -----------------------------------------------------------
-- Fourteen table rebuilds. Thirteen of the fourteen reference
-- `federation_keys`, which is itself one of the fourteen and carries a
-- SELF-FK (`scrub_key_id`, DEFERRABLE INITIALLY DEFERRED). V136's header
-- measured two things about that shape and both apply verbatim:
--
--   1. With `PRAGMA foreign_keys = ON` (set by SqliteBackend at every open)
--      a `DROP TABLE` is an implicit `DELETE FROM`, and that FIRES FOREIGN KEY
--      ACTIONS. `federation_keys` has a CASCADE from `federation_peer_metadata`
--      and `identity_canonical_binding`, and a RESTRICT from `goals`.
--      `federation_attestations` has a CASCADE from `attestation_subjects` and
--      a SET NULL from `identity_canonical_binding`. `federation_revocations`
--      has a CASCADE from `federation_revocation_quorum_state`. A naive drop
--      here would silently empty peer metadata, canonical bindings, subject
--      projections and quorum state — and report success — or be refused
--      outright by `goals`. `PRAGMA defer_foreign_keys` does not help: it
--      defers violation CHECKS, not cascade ACTIONS.
--
--   2. The `_new` + RENAME shape is REFUSED AT COMMIT on a self-FK table even
--      with every row consistent: rows in `_new` name the parent table
--      textually, the DROP pulls that table out from under them, and sqlite's
--      deferred-FK ledger is a COUNTER that the later RENAME never decrements.
--      `foreign_key_check` reports clean and COMMIT still fails.
--
-- So every one of the fourteen is rebuilt UNDER ITS FINAL NAME with the drop
-- made INERT: everything that references a table being dropped — directly, or
-- through a cascade it would fire — is staged and emptied leaf-first, the
-- table is dropped empty with empty referrers (no action fires, no counter
-- moves), re-created under its final name, and everything is restored
-- parent-first. Explicit column lists throughout, never `SELECT *`: a
-- migration runs against exactly one frozen schema (the V140 shape) and an
-- explicit list is auditable in a way `*` is not — and `federation_attestations`
-- carries a VIRTUAL generated column (`dimension`, V137) that `SELECT *` would
-- include and an INSERT cannot accept.
--
-- The six tables with no FKs in either direction (communities, families,
-- organizations, org_memberships, partner_records, transport_destinations)
-- would survive the `_new` + RENAME shape; they use this one anyway so the
-- file has ONE shape to audit, not two. Their DELETE step is omitted: with no
-- referrers and no FKs there is nothing a drop could fire.
--
-- Tables staged but NOT rebuilt (their DDL is untouched, only their rows
-- travel): attestation_subjects, identity_canonical_binding,
-- federation_revocation_quorum_state, goals, federation_peer_metadata,
-- edge_outbound_queue, edge_detection_events, federation_trust_grants.
-- The last three are NO ACTION referrers of `federation_keys` and would in
-- principle survive the drop via the deferred counter; they are staged so the
-- drop is inert by CONSTRUCTION rather than by counter arithmetic.
--
-- WHAT IS PRESERVED, VERBATIM
-- ---------------------------
-- Every column, in its existing declaration order (including the columns
-- earlier ALTERs appended after the original PRIMARY KEY clause), every type,
-- default, CHECK, PRIMARY KEY, FOREIGN KEY, the generated column, all 47
-- indexes and all 4 triggers (two on `federation_keys`, two on
-- `federation_attestations`), copied from the live V140 `sqlite_master`. A
-- rebuild is the one moment a constraint, an index or a trigger is silently
-- lost by transcription, so `v141_rebuild_...` in `store::sqlite` compares
-- `sqlite_master`, `table_xinfo` and `foreign_key_list` before and after for
-- each of the fourteen. The whole intended diff is fourteen `NOT NULL`s.
--
-- The `*_admitted` cursor indexes are DELIBERATELY kept on their
-- `COALESCE(admitted_at, <legacy>)` expressions even though the COALESCE is
-- now degenerate: the sqlite read doors spell that exact expression in their
-- WHERE / ORDER BY, and an expression index is used only when the query text
-- matches it. Simplifying the index and the fourteen reads together is a
-- separate, read-side cut.
--
-- Triggers are re-created AFTER the restore, so the restore INSERT is not
-- re-admitted through them — those rows were admitted under the triggers when
-- they were first written, and a trigger added after a row must not be given
-- a second chance to refuse it.

PRAGMA defer_foreign_keys = ON;

-- ══════════════════════════════════════════════════════════════════════════
-- 0. BACKFILL — before anything is staged, so the stage copies are complete
-- ══════════════════════════════════════════════════════════════════════════

UPDATE federation_attestations
   SET admitted_at = COALESCE(promoted_at, asserted_at) WHERE admitted_at IS NULL;
UPDATE federation_communities
   SET admitted_at = founded_at WHERE admitted_at IS NULL;
UPDATE federation_community_membership_revocations
   SET admitted_at = removed_at WHERE admitted_at IS NULL;
UPDATE federation_families
   SET admitted_at = founded_at WHERE admitted_at IS NULL;
UPDATE federation_family_membership_revocations
   SET admitted_at = removed_at WHERE admitted_at IS NULL;
UPDATE federation_identity_occurrence_revocations
   SET admitted_at = revoked_at WHERE admitted_at IS NULL;
UPDATE federation_identity_occurrences
   SET admitted_at = asserted_at WHERE admitted_at IS NULL;
UPDATE federation_keys
   SET admitted_at = scrub_timestamp WHERE admitted_at IS NULL;
UPDATE federation_location_proofs
   SET admitted_at = asserted_at WHERE admitted_at IS NULL;
UPDATE federation_organizations
   SET admitted_at = asserted_at WHERE admitted_at IS NULL;
UPDATE federation_org_memberships
   SET admitted_at = asserted_at WHERE admitted_at IS NULL;
UPDATE federation_partner_records
   SET admitted_at = asserted_at WHERE admitted_at IS NULL;
UPDATE federation_revocations
   SET admitted_at = scrub_timestamp WHERE admitted_at IS NULL;
UPDATE transport_destinations
   SET admitted_at = asserted_at WHERE admitted_at IS NULL;

-- ══════════════════════════════════════════════════════════════════════════
-- 1. STAGE every row involved
-- ══════════════════════════════════════════════════════════════════════════

-- ── 1a. the fourteen being rebuilt ───────────────────────────────────────

CREATE TABLE _v141_stage_keys AS
    SELECT key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm,
           identity_type, identity_ref, valid_from, valid_until,
           registration_envelope, original_content_hash,
           scrub_signature_classical, scrub_signature_pqc, scrub_key_id,
           scrub_timestamp, pqc_completed_at, persist_row_hash, consent_role,
           trust_type, trust_relationship, trust_domains, trusted_at,
           trusted_by, expires_at, roles, attestation_evidence,
           additional_scrubs, admitted_at, mutated_at
    FROM federation_keys;

CREATE TABLE _v141_stage_attestations AS
    SELECT attestation_id, attesting_key_id, attested_key_id, attestation_type,
           weight, asserted_at, expires_at, attestation_envelope,
           original_content_hash, scrub_signature_classical,
           scrub_signature_pqc, scrub_key_id, scrub_timestamp,
           pqc_completed_at, persist_row_hash, subject_key_ids,
           withdraws_admission_rule, cohort_scope, tier, promoted_at,
           additional_scrubs, admitted_at
    FROM federation_attestations;

CREATE TABLE _v141_stage_revocations AS
    SELECT revocation_id, revoked_key_id, revoking_key_id, reason, revoked_at,
           effective_at, revocation_envelope, original_content_hash,
           scrub_signature_classical, scrub_signature_pqc, scrub_key_id,
           scrub_timestamp, pqc_completed_at, persist_row_hash,
           observed_region, revoked_after, admitted_at
    FROM federation_revocations;

CREATE TABLE _v141_stage_identity_occurrences AS
    SELECT identity_key_id, occurrence_key_id, device_class,
           hardware_attestation, asserted_at, valid_until, persist_row_hash,
           pubkey_x25519_base64, pubkey_ml_kem_768_base64, attesting_key_id,
           signed_envelope, signature, transport_binding, admitted_at
    FROM federation_identity_occurrences;

CREATE TABLE _v141_stage_identity_occurrence_revocations AS
    SELECT identity_key_id, occurrence_key_id, revoked_at, effective_at,
           reason, witness_set, persist_row_hash, attesting_key_id,
           signed_envelope, signature, admitted_at
    FROM federation_identity_occurrence_revocations;

CREATE TABLE _v141_stage_family_membership_revocations AS
    SELECT family_key_id, removed_identity_key_id, removed_at, effective_at,
           reason, witness_set, persist_row_hash, authority_key_id,
           scrub_signature_classical, scrub_signature_pqc, admitted_at
    FROM federation_family_membership_revocations;

CREATE TABLE _v141_stage_community_membership_revocations AS
    SELECT community_key_id, removed_identity_key_id, removed_at, effective_at,
           reason, witness_set, persist_row_hash, authority_key_id,
           scrub_signature_classical, scrub_signature_pqc, admitted_at
    FROM federation_community_membership_revocations;

CREATE TABLE _v141_stage_location_proofs AS
    SELECT subject_key_id, cell_id, cell_resolution, asserted_at, valid_until,
           attestation_evidence, withdrawn_at, persist_row_hash,
           authority_key_id, scrub_signature_classical, scrub_signature_pqc,
           admitted_at
    FROM federation_location_proofs;

CREATE TABLE _v141_stage_communities AS
    SELECT community_key_id, community_name, members, founded_at,
           consensus_protocol, policy_blob, persist_row_hash, version,
           authority_key_id, scrub_signature_classical, scrub_signature_pqc,
           admitted_at
    FROM federation_communities;

CREATE TABLE _v141_stage_families AS
    SELECT family_key_id, family_name, members, founded_at, consensus_protocol,
           consensus_protocol_entrenched, persist_row_hash, version,
           authority_key_id, scrub_signature_classical, scrub_signature_pqc,
           admitted_at
    FROM federation_families;

CREATE TABLE _v141_stage_organizations AS
    SELECT attestation_id, org_id, name, org_type, parent_org_id, partner_id,
           status, asserted_at, valid_until, attesting_key_id, signed_envelope,
           ed25519_signature_base64, mldsa65_signature_base64, withdrawn_at,
           persist_row_hash, admitted_at
    FROM federation_organizations;

CREATE TABLE _v141_stage_org_memberships AS
    SELECT attestation_id, user_id, org_id, role, status, asserted_at,
           valid_until, attesting_key_id, signed_envelope,
           ed25519_signature_base64, mldsa65_signature_base64, withdrawn_at,
           persist_row_hash, admitted_at
    FROM federation_org_memberships;

CREATE TABLE _v141_stage_partner_records AS
    SELECT attestation_id, license_id, partner_id, org_id, license_type,
           max_autonomy_tier, requires_supervisor, deployment_limit,
           offline_grace_hours, status, revision, issued_at, expires_at,
           asserted_at, signed_envelope, withdrawn_at, persist_row_hash,
           steward_signatures, threshold, admitted_at
    FROM federation_partner_records;

CREATE TABLE _v141_stage_transport_destinations AS
    SELECT occurrence_key_id, transport_kind, destination, asserted_at,
           last_seen_at, transport_ed25519_pubkey_base64,
           transport_x25519_pubkey_base64, binding_provenance, epoch,
           retired_at, attesting_key_id, signed_envelope, signature,
           admitted_at
    FROM transport_destinations;

-- ── 1b. referrers that are NOT rebuilt — rows travel, DDL stays ──────────

CREATE TABLE _v141_stage_attestation_subjects AS
    SELECT subject_key_id, dimension, asserted_at, attestation_id, tier,
           cohort_scope
    FROM attestation_subjects;

CREATE TABLE _v141_stage_identity_canonical_binding AS
    SELECT canonical_hash, federation_key_id, bound_at, binding_attestation_id,
           inserted_at
    FROM identity_canonical_binding;

CREATE TABLE _v141_stage_revocation_quorum_state AS
    SELECT revocation_id, us_observed_at, eu_observed_at, apac_observed_at,
           quorum_reached_at, quorum_weight, updated_at
    FROM federation_revocation_quorum_state;

CREATE TABLE _v141_stage_goals AS
    SELECT goal_id, declared_by_key_id, declared_at, goal_text,
           goal_text_canonical, scope_kind, scope_cohort_id, meta_dimension,
           meta_rationale, meta_deliberation, retired_at, inserted_at,
           persist_row_hash
    FROM goals;

CREATE TABLE _v141_stage_peer_metadata AS
    SELECT key_id, alias, trust, notes, policy_blob, transport_identity,
           removed_at, inserted_at, updated_at, persist_row_hash
    FROM federation_peer_metadata;

CREATE TABLE _v141_stage_edge_outbound_queue AS
    SELECT queue_id, sender_key_id, destination_key_id, message_type,
           edge_schema_version, envelope_bytes, body_sha256, body_size_bytes,
           status, enqueued_at, next_attempt_after, last_attempt_at,
           transport_delivered_at, delivered_at, abandoned_at,
           abandoned_reason, attempt_count, max_attempts, ttl_seconds,
           last_error_class, last_error_detail, last_transport, requires_ack,
           ack_timeout_seconds, ack_envelope_bytes, ack_received_at,
           claimed_until, claimed_by
    FROM edge_outbound_queue;

CREATE TABLE _v141_stage_edge_detection_events AS
    SELECT detection_id, tenant_id, detector_kind, subject_key_id,
           observed_at, evidence, severity, signature, signing_key_id,
           signature_verified, persist_row_hash
    FROM edge_detection_events;

CREATE TABLE _v141_stage_trust_grants AS
    SELECT grant_id, grantee_key, granter_key, purpose, scope, granted_at,
           expires_at, revoked_at, revoked_by, chain_event_id,
           chain_event_hash, tenant_id
    FROM federation_trust_grants;

-- ══════════════════════════════════════════════════════════════════════════
-- 2. EMPTY, leaf-first, so every DROP below is inert
-- ══════════════════════════════════════════════════════════════════════════
-- Grandchildren (they reference tables that reference federation_keys) …
DELETE FROM attestation_subjects;
DELETE FROM identity_canonical_binding;
DELETE FROM federation_revocation_quorum_state;
-- … children of federation_keys that are staged only …
DELETE FROM goals;
DELETE FROM federation_peer_metadata;
DELETE FROM edge_outbound_queue;
DELETE FROM edge_detection_events;
DELETE FROM federation_trust_grants;
-- … children of federation_keys that are rebuilt …
DELETE FROM federation_attestations;
DELETE FROM federation_revocations;
DELETE FROM federation_identity_occurrences;
DELETE FROM federation_identity_occurrence_revocations;
DELETE FROM federation_family_membership_revocations;
DELETE FROM federation_community_membership_revocations;
DELETE FROM federation_location_proofs;
-- … and the root. Its self-FK is INITIALLY DEFERRED and the statement leaves
-- the table empty, so the ledger nets to zero before the drop.
DELETE FROM federation_keys;

-- ══════════════════════════════════════════════════════════════════════════
-- 3. REBUILD each of the fourteen UNDER ITS FINAL NAME
-- ══════════════════════════════════════════════════════════════════════════

-- ── federation_keys (V004 + V015/V016/V019/V040/V102/V126/V131 columns) ──
DROP TABLE federation_keys;
CREATE TABLE federation_keys (
    key_id                    TEXT PRIMARY KEY,
    pubkey_ed25519_base64     TEXT NOT NULL,
    pubkey_ml_dsa_65_base64   TEXT,
    algorithm                 TEXT NOT NULL CHECK (algorithm = 'hybrid'),
    identity_type             TEXT NOT NULL,
    identity_ref              TEXT NOT NULL,
    valid_from                TEXT NOT NULL,
    valid_until               TEXT,
    registration_envelope     TEXT NOT NULL,
    original_content_hash      BLOB NOT NULL,
    scrub_signature_classical  TEXT NOT NULL,
    scrub_signature_pqc        TEXT,
    scrub_key_id               TEXT NOT NULL,
    scrub_timestamp            TEXT NOT NULL,
    pqc_completed_at           TEXT,
    persist_row_hash           TEXT NOT NULL,
    consent_role               TEXT NOT NULL DEFAULT 'unregistered',
    trust_type                 TEXT NOT NULL DEFAULT 'temporary',
    trust_relationship         TEXT NOT NULL DEFAULT 'direct',
    trust_domains              TEXT,
    trusted_at                 TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    trusted_by                 TEXT,
    expires_at                 TEXT,
    roles                      TEXT,
    attestation_evidence       TEXT,
    additional_scrubs          TEXT NOT NULL DEFAULT '[]',
    -- CIRISPersist#828 — NOT NULL, as on postgres since V126.
    admitted_at                TEXT NOT NULL,
    mutated_at                 TEXT,
    FOREIGN KEY (scrub_key_id) REFERENCES federation_keys(key_id) DEFERRABLE INITIALLY DEFERRED
);

-- ── federation_attestations ──────────────────────────────────────────────
DROP TABLE federation_attestations;
CREATE TABLE federation_attestations (
    attestation_id        TEXT PRIMARY KEY,
    attesting_key_id      TEXT NOT NULL REFERENCES federation_keys(key_id),
    attested_key_id       TEXT NOT NULL,
    attestation_type      TEXT NOT NULL,
    weight                REAL,
    asserted_at           TEXT NOT NULL,
    expires_at            TEXT,
    attestation_envelope  TEXT NOT NULL,
    original_content_hash      BLOB NOT NULL,
    scrub_signature_classical  TEXT NOT NULL,
    scrub_signature_pqc        TEXT,
    scrub_key_id               TEXT NOT NULL REFERENCES federation_keys(key_id),
    scrub_timestamp            TEXT NOT NULL,
    pqc_completed_at           TEXT,
    persist_row_hash           TEXT NOT NULL,
    subject_key_ids            TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(subject_key_ids)
               AND json_type(subject_key_ids) = 'array'),
    withdraws_admission_rule   INTEGER
        CHECK (withdraws_admission_rule IS NULL
               OR withdraws_admission_rule BETWEEN 1 AND 5),
    cohort_scope               TEXT NOT NULL DEFAULT 'federation'
        CHECK (cohort_scope IN (
            'self', 'family', 'community',
            'affiliations', 'species', 'biosphere', 'federation'
        )),
    tier                       TEXT NOT NULL DEFAULT 'federation'
        CHECK (tier IN ('local', 'federation')),
    promoted_at                TEXT,
    additional_scrubs          TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(additional_scrubs)
               AND json_type(additional_scrubs) = 'array'),
    dimension                  TEXT
        GENERATED ALWAYS AS (json_extract(attestation_envelope, '$.dimension')) VIRTUAL,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at                TEXT NOT NULL
);

-- ── federation_revocations ───────────────────────────────────────────────
DROP TABLE federation_revocations;
CREATE TABLE federation_revocations (
    revocation_id         TEXT PRIMARY KEY,
    revoked_key_id        TEXT NOT NULL REFERENCES federation_keys(key_id),
    revoking_key_id       TEXT NOT NULL REFERENCES federation_keys(key_id),
    reason                TEXT,
    revoked_at            TEXT NOT NULL,
    effective_at          TEXT NOT NULL,
    revocation_envelope   TEXT NOT NULL,
    original_content_hash      BLOB NOT NULL,
    scrub_signature_classical  TEXT NOT NULL,
    scrub_signature_pqc        TEXT,
    scrub_key_id               TEXT NOT NULL REFERENCES federation_keys(key_id),
    scrub_timestamp            TEXT NOT NULL,
    pqc_completed_at           TEXT,
    persist_row_hash           TEXT NOT NULL,
    observed_region            TEXT NOT NULL DEFAULT 'us'
        CHECK (observed_region IN ('us', 'eu', 'apac')),
    revoked_after              TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V123.
    admitted_at                TEXT NOT NULL
);

-- ── federation_identity_occurrences ──────────────────────────────────────
DROP TABLE federation_identity_occurrences;
CREATE TABLE federation_identity_occurrences (
    identity_key_id       TEXT NOT NULL
        REFERENCES federation_keys(key_id),
    occurrence_key_id     TEXT NOT NULL
        REFERENCES federation_keys(key_id),
    device_class          TEXT NOT NULL
        CHECK (device_class IN ('phone', 'laptop', 'server', 'embedded',
                                 'agent', 'service')),
    hardware_attestation  TEXT,
    asserted_at           TEXT NOT NULL,
    valid_until           TEXT,
    persist_row_hash      TEXT NOT NULL,
    pubkey_x25519_base64      TEXT,
    pubkey_ml_kem_768_base64  TEXT,
    attesting_key_id      TEXT,
    signed_envelope       TEXT,
    signature             TEXT,
    transport_binding     TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at           TEXT NOT NULL,
    PRIMARY KEY (identity_key_id, occurrence_key_id)
);

-- ── federation_identity_occurrence_revocations ───────────────────────────
DROP TABLE federation_identity_occurrence_revocations;
CREATE TABLE federation_identity_occurrence_revocations (
    identity_key_id     TEXT NOT NULL REFERENCES federation_keys(key_id),
    occurrence_key_id   TEXT NOT NULL REFERENCES federation_keys(key_id),
    revoked_at          TEXT NOT NULL,
    effective_at        TEXT NOT NULL,
    reason              TEXT,
    witness_set         TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(witness_set) AND json_type(witness_set) = 'array'),
    persist_row_hash    TEXT NOT NULL,
    attesting_key_id    TEXT,
    signed_envelope     TEXT,
    signature           TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at         TEXT NOT NULL,
    PRIMARY KEY (identity_key_id, occurrence_key_id)
);

-- ── federation_family_membership_revocations ─────────────────────────────
DROP TABLE federation_family_membership_revocations;
CREATE TABLE federation_family_membership_revocations (
    family_key_id            TEXT NOT NULL REFERENCES federation_keys(key_id),
    removed_identity_key_id  TEXT NOT NULL REFERENCES federation_keys(key_id),
    removed_at               TEXT NOT NULL,
    effective_at             TEXT NOT NULL,
    reason                   TEXT,
    witness_set              TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(witness_set) AND json_type(witness_set) = 'array'),
    persist_row_hash         TEXT NOT NULL,
    authority_key_id         TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc      TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at              TEXT NOT NULL,
    PRIMARY KEY (family_key_id, removed_identity_key_id)
);

-- ── federation_community_membership_revocations ──────────────────────────
DROP TABLE federation_community_membership_revocations;
CREATE TABLE federation_community_membership_revocations (
    community_key_id         TEXT NOT NULL REFERENCES federation_keys(key_id),
    removed_identity_key_id  TEXT NOT NULL REFERENCES federation_keys(key_id),
    removed_at               TEXT NOT NULL,
    effective_at             TEXT NOT NULL,
    reason                   TEXT,
    witness_set              TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(witness_set) AND json_type(witness_set) = 'array'),
    persist_row_hash         TEXT NOT NULL,
    authority_key_id         TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc      TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at              TEXT NOT NULL,
    PRIMARY KEY (community_key_id, removed_identity_key_id)
);

-- ── federation_location_proofs ───────────────────────────────────────────
DROP TABLE federation_location_proofs;
CREATE TABLE federation_location_proofs (
    subject_key_id        TEXT NOT NULL REFERENCES federation_keys(key_id),
    cell_id               TEXT NOT NULL,
    cell_resolution       INTEGER NOT NULL
        CHECK (cell_resolution BETWEEN 0 AND 15),
    asserted_at           TEXT NOT NULL,
    valid_until           TEXT,
    attestation_evidence  BLOB,
    withdrawn_at          TEXT,
    persist_row_hash      TEXT NOT NULL,
    authority_key_id      TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc   TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at           TEXT NOT NULL,
    PRIMARY KEY (subject_key_id, asserted_at)
);

-- ── federation_communities ───────────────────────────────────────────────
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
    CHECK (consensus_protocol GLOB 'founder_only'
        OR consensus_protocol GLOB 'unanimous'
        OR consensus_protocol GLOB 'majority'
        OR consensus_protocol GLOB 'quorum:*/*'
        OR consensus_protocol GLOB 'reverse_quorum:*/*:*'
        OR consensus_protocol GLOB 'weighted:?*'
        OR consensus_protocol GLOB 'custom:?*')
);

-- ── federation_families ──────────────────────────────────────────────────
DROP TABLE federation_families;
CREATE TABLE federation_families (
    family_key_id                   TEXT PRIMARY KEY,
    family_name                     TEXT NOT NULL,
    members                         TEXT NOT NULL DEFAULT '[]'
        CHECK (json_type(members) = 'array'),
    founded_at                      TEXT NOT NULL,
    consensus_protocol              TEXT NOT NULL,
    consensus_protocol_entrenched   INTEGER NOT NULL DEFAULT 0
        CHECK (consensus_protocol_entrenched IN (0, 1)),
    persist_row_hash                TEXT NOT NULL,
    version                         INTEGER NOT NULL DEFAULT 1,
    authority_key_id                TEXT,
    scrub_signature_classical       TEXT,
    scrub_signature_pqc             TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at                     TEXT NOT NULL
);

-- ── federation_organizations ─────────────────────────────────────────────
DROP TABLE federation_organizations;
CREATE TABLE federation_organizations (
    attestation_id            TEXT NOT NULL PRIMARY KEY,
    org_id                    TEXT NOT NULL,
    name                      TEXT NOT NULL,
    org_type                  TEXT NOT NULL,
    parent_org_id             TEXT,
    partner_id                TEXT,
    status                    TEXT NOT NULL,
    asserted_at               TEXT NOT NULL,
    valid_until               TEXT,
    attesting_key_id          TEXT NOT NULL,
    signed_envelope           TEXT NOT NULL,
    ed25519_signature_base64  TEXT NOT NULL,
    mldsa65_signature_base64  TEXT,
    withdrawn_at              TEXT,
    persist_row_hash          TEXT NOT NULL,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at               TEXT NOT NULL
);

-- ── federation_org_memberships ───────────────────────────────────────────
DROP TABLE federation_org_memberships;
CREATE TABLE federation_org_memberships (
    attestation_id            TEXT NOT NULL PRIMARY KEY,
    user_id                   TEXT NOT NULL,
    org_id                    TEXT NOT NULL,
    role                      TEXT NOT NULL,
    status                    TEXT NOT NULL,
    asserted_at               TEXT NOT NULL,
    valid_until               TEXT,
    attesting_key_id          TEXT NOT NULL,
    signed_envelope           TEXT NOT NULL,
    ed25519_signature_base64  TEXT NOT NULL,
    mldsa65_signature_base64  TEXT,
    withdrawn_at              TEXT,
    persist_row_hash          TEXT NOT NULL,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at               TEXT NOT NULL
);

-- ── federation_partner_records ───────────────────────────────────────────
DROP TABLE federation_partner_records;
CREATE TABLE federation_partner_records (
    attestation_id            TEXT NOT NULL PRIMARY KEY,
    license_id                TEXT NOT NULL,
    partner_id                TEXT NOT NULL,
    org_id                    TEXT NOT NULL,
    license_type              TEXT NOT NULL,
    max_autonomy_tier         TEXT NOT NULL,
    requires_supervisor       INTEGER NOT NULL,
    deployment_limit          INTEGER NOT NULL,
    offline_grace_hours       INTEGER NOT NULL,
    status                    TEXT NOT NULL,
    revision                  INTEGER NOT NULL,
    issued_at                 TEXT NOT NULL,
    expires_at                TEXT NOT NULL,
    asserted_at               TEXT NOT NULL,
    signed_envelope           TEXT NOT NULL,
    withdrawn_at              TEXT,
    persist_row_hash          TEXT NOT NULL,
    steward_signatures        TEXT NOT NULL DEFAULT '[]',
    threshold                 INTEGER NOT NULL DEFAULT 0,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at               TEXT NOT NULL
);

-- ── transport_destinations ───────────────────────────────────────────────
DROP TABLE transport_destinations;
CREATE TABLE transport_destinations (
    occurrence_key_id               TEXT NOT NULL,
    transport_kind                  TEXT NOT NULL,
    destination                     TEXT NOT NULL,
    asserted_at                     TEXT NOT NULL,
    last_seen_at                    TEXT,
    transport_ed25519_pubkey_base64 TEXT,
    transport_x25519_pubkey_base64  TEXT,
    binding_provenance              TEXT NOT NULL DEFAULT 'rooted',
    epoch                           INTEGER NOT NULL DEFAULT 0,
    retired_at                      TEXT,
    attesting_key_id                TEXT,
    signed_envelope                 TEXT,
    signature                       TEXT,
    -- CIRISPersist#828 — NOT NULL, as on postgres since V130.
    admitted_at                     TEXT NOT NULL,
    PRIMARY KEY (occurrence_key_id, transport_kind)
);

-- ══════════════════════════════════════════════════════════════════════════
-- 4. RESTORE, parent-first
-- ══════════════════════════════════════════════════════════════════════════

-- The root. Rows come back in their original rowid order; a scrub_key_id that
-- names a later row is a deferred violation that the later row clears.
INSERT INTO federation_keys
    (key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm,
     identity_type, identity_ref, valid_from, valid_until,
     registration_envelope, original_content_hash, scrub_signature_classical,
     scrub_signature_pqc, scrub_key_id, scrub_timestamp, pqc_completed_at,
     persist_row_hash, consent_role, trust_type, trust_relationship,
     trust_domains, trusted_at, trusted_by, expires_at, roles,
     attestation_evidence, additional_scrubs, admitted_at, mutated_at)
SELECT key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm,
       identity_type, identity_ref, valid_from, valid_until,
       registration_envelope, original_content_hash, scrub_signature_classical,
       scrub_signature_pqc, scrub_key_id, scrub_timestamp, pqc_completed_at,
       persist_row_hash, consent_role, trust_type, trust_relationship,
       trust_domains, trusted_at, trusted_by, expires_at, roles,
       attestation_evidence, additional_scrubs, admitted_at, mutated_at
FROM _v141_stage_keys;

-- Children of federation_keys that were rebuilt.
INSERT INTO federation_attestations
    (attestation_id, attesting_key_id, attested_key_id, attestation_type,
     weight, asserted_at, expires_at, attestation_envelope,
     original_content_hash, scrub_signature_classical, scrub_signature_pqc,
     scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash,
     subject_key_ids, withdraws_admission_rule, cohort_scope, tier,
     promoted_at, additional_scrubs, admitted_at)
SELECT attestation_id, attesting_key_id, attested_key_id, attestation_type,
       weight, asserted_at, expires_at, attestation_envelope,
       original_content_hash, scrub_signature_classical, scrub_signature_pqc,
       scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash,
       subject_key_ids, withdraws_admission_rule, cohort_scope, tier,
       promoted_at, additional_scrubs, admitted_at
FROM _v141_stage_attestations;

INSERT INTO federation_revocations
    (revocation_id, revoked_key_id, revoking_key_id, reason, revoked_at,
     effective_at, revocation_envelope, original_content_hash,
     scrub_signature_classical, scrub_signature_pqc, scrub_key_id,
     scrub_timestamp, pqc_completed_at, persist_row_hash, observed_region,
     revoked_after, admitted_at)
SELECT revocation_id, revoked_key_id, revoking_key_id, reason, revoked_at,
       effective_at, revocation_envelope, original_content_hash,
       scrub_signature_classical, scrub_signature_pqc, scrub_key_id,
       scrub_timestamp, pqc_completed_at, persist_row_hash, observed_region,
       revoked_after, admitted_at
FROM _v141_stage_revocations;

INSERT INTO federation_identity_occurrences
    (identity_key_id, occurrence_key_id, device_class, hardware_attestation,
     asserted_at, valid_until, persist_row_hash, pubkey_x25519_base64,
     pubkey_ml_kem_768_base64, attesting_key_id, signed_envelope, signature,
     transport_binding, admitted_at)
SELECT identity_key_id, occurrence_key_id, device_class, hardware_attestation,
       asserted_at, valid_until, persist_row_hash, pubkey_x25519_base64,
       pubkey_ml_kem_768_base64, attesting_key_id, signed_envelope, signature,
       transport_binding, admitted_at
FROM _v141_stage_identity_occurrences;

INSERT INTO federation_identity_occurrence_revocations
    (identity_key_id, occurrence_key_id, revoked_at, effective_at, reason,
     witness_set, persist_row_hash, attesting_key_id, signed_envelope,
     signature, admitted_at)
SELECT identity_key_id, occurrence_key_id, revoked_at, effective_at, reason,
       witness_set, persist_row_hash, attesting_key_id, signed_envelope,
       signature, admitted_at
FROM _v141_stage_identity_occurrence_revocations;

INSERT INTO federation_family_membership_revocations
    (family_key_id, removed_identity_key_id, removed_at, effective_at, reason,
     witness_set, persist_row_hash, authority_key_id,
     scrub_signature_classical, scrub_signature_pqc, admitted_at)
SELECT family_key_id, removed_identity_key_id, removed_at, effective_at, reason,
       witness_set, persist_row_hash, authority_key_id,
       scrub_signature_classical, scrub_signature_pqc, admitted_at
FROM _v141_stage_family_membership_revocations;

INSERT INTO federation_community_membership_revocations
    (community_key_id, removed_identity_key_id, removed_at, effective_at,
     reason, witness_set, persist_row_hash, authority_key_id,
     scrub_signature_classical, scrub_signature_pqc, admitted_at)
SELECT community_key_id, removed_identity_key_id, removed_at, effective_at,
       reason, witness_set, persist_row_hash, authority_key_id,
       scrub_signature_classical, scrub_signature_pqc, admitted_at
FROM _v141_stage_community_membership_revocations;

INSERT INTO federation_location_proofs
    (subject_key_id, cell_id, cell_resolution, asserted_at, valid_until,
     attestation_evidence, withdrawn_at, persist_row_hash, authority_key_id,
     scrub_signature_classical, scrub_signature_pqc, admitted_at)
SELECT subject_key_id, cell_id, cell_resolution, asserted_at, valid_until,
       attestation_evidence, withdrawn_at, persist_row_hash, authority_key_id,
       scrub_signature_classical, scrub_signature_pqc, admitted_at
FROM _v141_stage_location_proofs;

-- Children of federation_keys that were staged only.
INSERT INTO goals
    (goal_id, declared_by_key_id, declared_at, goal_text, goal_text_canonical,
     scope_kind, scope_cohort_id, meta_dimension, meta_rationale,
     meta_deliberation, retired_at, inserted_at, persist_row_hash)
SELECT goal_id, declared_by_key_id, declared_at, goal_text, goal_text_canonical,
       scope_kind, scope_cohort_id, meta_dimension, meta_rationale,
       meta_deliberation, retired_at, inserted_at, persist_row_hash
FROM _v141_stage_goals;

INSERT INTO federation_peer_metadata
    (key_id, alias, trust, notes, policy_blob, transport_identity, removed_at,
     inserted_at, updated_at, persist_row_hash)
SELECT key_id, alias, trust, notes, policy_blob, transport_identity, removed_at,
       inserted_at, updated_at, persist_row_hash
FROM _v141_stage_peer_metadata;

INSERT INTO edge_outbound_queue
    (queue_id, sender_key_id, destination_key_id, message_type,
     edge_schema_version, envelope_bytes, body_sha256, body_size_bytes,
     status, enqueued_at, next_attempt_after, last_attempt_at,
     transport_delivered_at, delivered_at, abandoned_at, abandoned_reason,
     attempt_count, max_attempts, ttl_seconds, last_error_class,
     last_error_detail, last_transport, requires_ack, ack_timeout_seconds,
     ack_envelope_bytes, ack_received_at, claimed_until, claimed_by)
SELECT queue_id, sender_key_id, destination_key_id, message_type,
       edge_schema_version, envelope_bytes, body_sha256, body_size_bytes,
       status, enqueued_at, next_attempt_after, last_attempt_at,
       transport_delivered_at, delivered_at, abandoned_at, abandoned_reason,
       attempt_count, max_attempts, ttl_seconds, last_error_class,
       last_error_detail, last_transport, requires_ack, ack_timeout_seconds,
       ack_envelope_bytes, ack_received_at, claimed_until, claimed_by
FROM _v141_stage_edge_outbound_queue;

INSERT INTO edge_detection_events
    (detection_id, tenant_id, detector_kind, subject_key_id, observed_at,
     evidence, severity, signature, signing_key_id, signature_verified,
     persist_row_hash)
SELECT detection_id, tenant_id, detector_kind, subject_key_id, observed_at,
       evidence, severity, signature, signing_key_id, signature_verified,
       persist_row_hash
FROM _v141_stage_edge_detection_events;

INSERT INTO federation_trust_grants
    (grant_id, grantee_key, granter_key, purpose, scope, granted_at,
     expires_at, revoked_at, revoked_by, chain_event_id, chain_event_hash,
     tenant_id)
SELECT grant_id, grantee_key, granter_key, purpose, scope, granted_at,
       expires_at, revoked_at, revoked_by, chain_event_id, chain_event_hash,
       tenant_id
FROM _v141_stage_trust_grants;

-- Grandchildren last: they need both federation_keys and their direct parent.
INSERT INTO attestation_subjects
    (subject_key_id, dimension, asserted_at, attestation_id, tier, cohort_scope)
SELECT subject_key_id, dimension, asserted_at, attestation_id, tier, cohort_scope
FROM _v141_stage_attestation_subjects;

INSERT INTO identity_canonical_binding
    (canonical_hash, federation_key_id, bound_at, binding_attestation_id,
     inserted_at)
SELECT canonical_hash, federation_key_id, bound_at, binding_attestation_id,
       inserted_at
FROM _v141_stage_identity_canonical_binding;

INSERT INTO federation_revocation_quorum_state
    (revocation_id, us_observed_at, eu_observed_at, apac_observed_at,
     quorum_reached_at, quorum_weight, updated_at)
SELECT revocation_id, us_observed_at, eu_observed_at, apac_observed_at,
       quorum_reached_at, quorum_weight, updated_at
FROM _v141_stage_revocation_quorum_state;

-- The six with no FKs in either direction.
INSERT INTO federation_communities
    (community_key_id, community_name, members, founded_at,
     consensus_protocol, policy_blob, persist_row_hash, version,
     authority_key_id, scrub_signature_classical, scrub_signature_pqc,
     admitted_at)
SELECT community_key_id, community_name, members, founded_at,
       consensus_protocol, policy_blob, persist_row_hash, version,
       authority_key_id, scrub_signature_classical, scrub_signature_pqc,
       admitted_at
FROM _v141_stage_communities;

INSERT INTO federation_families
    (family_key_id, family_name, members, founded_at, consensus_protocol,
     consensus_protocol_entrenched, persist_row_hash, version,
     authority_key_id, scrub_signature_classical, scrub_signature_pqc,
     admitted_at)
SELECT family_key_id, family_name, members, founded_at, consensus_protocol,
       consensus_protocol_entrenched, persist_row_hash, version,
       authority_key_id, scrub_signature_classical, scrub_signature_pqc,
       admitted_at
FROM _v141_stage_families;

INSERT INTO federation_organizations
    (attestation_id, org_id, name, org_type, parent_org_id, partner_id, status,
     asserted_at, valid_until, attesting_key_id, signed_envelope,
     ed25519_signature_base64, mldsa65_signature_base64, withdrawn_at,
     persist_row_hash, admitted_at)
SELECT attestation_id, org_id, name, org_type, parent_org_id, partner_id, status,
       asserted_at, valid_until, attesting_key_id, signed_envelope,
       ed25519_signature_base64, mldsa65_signature_base64, withdrawn_at,
       persist_row_hash, admitted_at
FROM _v141_stage_organizations;

INSERT INTO federation_org_memberships
    (attestation_id, user_id, org_id, role, status, asserted_at, valid_until,
     attesting_key_id, signed_envelope, ed25519_signature_base64,
     mldsa65_signature_base64, withdrawn_at, persist_row_hash, admitted_at)
SELECT attestation_id, user_id, org_id, role, status, asserted_at, valid_until,
       attesting_key_id, signed_envelope, ed25519_signature_base64,
       mldsa65_signature_base64, withdrawn_at, persist_row_hash, admitted_at
FROM _v141_stage_org_memberships;

INSERT INTO federation_partner_records
    (attestation_id, license_id, partner_id, org_id, license_type,
     max_autonomy_tier, requires_supervisor, deployment_limit,
     offline_grace_hours, status, revision, issued_at, expires_at,
     asserted_at, signed_envelope, withdrawn_at, persist_row_hash,
     steward_signatures, threshold, admitted_at)
SELECT attestation_id, license_id, partner_id, org_id, license_type,
       max_autonomy_tier, requires_supervisor, deployment_limit,
       offline_grace_hours, status, revision, issued_at, expires_at,
       asserted_at, signed_envelope, withdrawn_at, persist_row_hash,
       steward_signatures, threshold, admitted_at
FROM _v141_stage_partner_records;

INSERT INTO transport_destinations
    (occurrence_key_id, transport_kind, destination, asserted_at,
     last_seen_at, transport_ed25519_pubkey_base64,
     transport_x25519_pubkey_base64, binding_provenance, epoch, retired_at,
     attesting_key_id, signed_envelope, signature, admitted_at)
SELECT occurrence_key_id, transport_kind, destination, asserted_at,
       last_seen_at, transport_ed25519_pubkey_base64,
       transport_x25519_pubkey_base64, binding_provenance, epoch, retired_at,
       attesting_key_id, signed_envelope, signature, admitted_at
FROM _v141_stage_transport_destinations;

DROP TABLE _v141_stage_keys;
DROP TABLE _v141_stage_attestations;
DROP TABLE _v141_stage_revocations;
DROP TABLE _v141_stage_identity_occurrences;
DROP TABLE _v141_stage_identity_occurrence_revocations;
DROP TABLE _v141_stage_family_membership_revocations;
DROP TABLE _v141_stage_community_membership_revocations;
DROP TABLE _v141_stage_location_proofs;
DROP TABLE _v141_stage_communities;
DROP TABLE _v141_stage_families;
DROP TABLE _v141_stage_organizations;
DROP TABLE _v141_stage_org_memberships;
DROP TABLE _v141_stage_partner_records;
DROP TABLE _v141_stage_transport_destinations;
DROP TABLE _v141_stage_attestation_subjects;
DROP TABLE _v141_stage_identity_canonical_binding;
DROP TABLE _v141_stage_revocation_quorum_state;
DROP TABLE _v141_stage_goals;
DROP TABLE _v141_stage_peer_metadata;
DROP TABLE _v141_stage_edge_outbound_queue;
DROP TABLE _v141_stage_edge_detection_events;
DROP TABLE _v141_stage_trust_grants;

-- ══════════════════════════════════════════════════════════════════════════
-- 5. INDEXES — every index of the fourteen, verbatim from the V140 shape
-- ══════════════════════════════════════════════════════════════════════════

-- federation_keys (V004, V015, V019, V040, V102, V131)
CREATE INDEX federation_keys_identity
    ON federation_keys (identity_type, identity_ref);
CREATE INDEX federation_keys_scrub_key
    ON federation_keys (scrub_key_id);
CREATE INDEX federation_keys_trust_relationship
    ON federation_keys (trust_relationship);
CREATE INDEX federation_keys_expires_at
    ON federation_keys (expires_at);
CREATE INDEX federation_keys_accord_holder_evidence
    ON federation_keys (key_id)
    WHERE identity_type = 'accord_holder';
CREATE INDEX federation_keys_consent_role
    ON federation_keys (consent_role)
    WHERE consent_role <> 'unregistered';
CREATE INDEX federation_keys_serve_position
    ON federation_keys (
        MAX(COALESCE(admitted_at, scrub_timestamp),
            COALESCE(mutated_at, COALESCE(admitted_at, scrub_timestamp))),
        key_id
    );

-- federation_attestations (V004, V060, V064, V066, V078, V101, V130, V137)
CREATE INDEX federation_attestations_attested
    ON federation_attestations (attested_key_id, asserted_at DESC);
CREATE INDEX federation_attestations_attesting
    ON federation_attestations (attesting_key_id, asserted_at DESC);
CREATE INDEX federation_attestations_withdraws_admission_rule_idx
    ON federation_attestations (withdraws_admission_rule)
    WHERE withdraws_admission_rule IS NOT NULL;
CREATE INDEX federation_attestations_cohort_scope
    ON federation_attestations (cohort_scope)
    WHERE cohort_scope != 'federation';
CREATE INDEX idx_federation_attestations_v060_by_target
    ON federation_attestations (attested_key_id, cohort_scope, asserted_at DESC);
CREATE INDEX idx_federation_attestations_v060_emitter_scope
    ON federation_attestations (scrub_key_id, cohort_scope);
CREATE INDEX federation_attestations_local_tier
    ON federation_attestations (tier)
    WHERE tier = 'local';
CREATE INDEX federation_attestations_composer_ref
    ON federation_attestations (
        attesting_key_id,
        attestation_type,
        json_extract(attestation_envelope, '$.references_attestation_id')
    );
CREATE INDEX federation_attestations_admitted
    ON federation_attestations
       (COALESCE(admitted_at, promoted_at, asserted_at), attestation_id);
CREATE INDEX federation_attestations_attester_dimension
    ON federation_attestations (attesting_key_id, dimension);

-- federation_revocations (V004, V038, V123)
CREATE INDEX federation_revocations_revoked
    ON federation_revocations (revoked_key_id, effective_at DESC);
CREATE INDEX federation_revocations_observed_region
    ON federation_revocations (observed_region, revoked_key_id, scrub_timestamp DESC)
    WHERE observed_region != 'us';
CREATE INDEX federation_revocations_admitted
    ON federation_revocations (COALESCE(admitted_at, scrub_timestamp), revocation_id);

-- federation_identity_occurrences (V071, V130)
CREATE INDEX federation_identity_occurrences_by_identity
    ON federation_identity_occurrences (identity_key_id);
CREATE INDEX federation_identity_occurrences_by_occurrence_live
    ON federation_identity_occurrences (occurrence_key_id)
    WHERE valid_until IS NULL;
CREATE INDEX federation_identity_occurrences_by_occurrence_all
    ON federation_identity_occurrences (occurrence_key_id);
CREATE INDEX federation_identity_occurrences_admitted
    ON federation_identity_occurrences
       (COALESCE(admitted_at, asserted_at), identity_key_id, occurrence_key_id);

-- federation_identity_occurrence_revocations (V071, V130)
CREATE INDEX federation_identity_occurrence_revocations_effective
    ON federation_identity_occurrence_revocations (effective_at);
CREATE INDEX federation_identity_occurrence_revocations_by_occurrence
    ON federation_identity_occurrence_revocations (occurrence_key_id);
CREATE INDEX federation_identity_occurrence_revocations_admitted
    ON federation_identity_occurrence_revocations
       (COALESCE(admitted_at, revoked_at), identity_key_id, occurrence_key_id);

-- federation_family_membership_revocations (V071, V130)
CREATE INDEX federation_family_membership_revocations_effective
    ON federation_family_membership_revocations (effective_at);
CREATE INDEX federation_family_membership_revocations_by_member
    ON federation_family_membership_revocations (removed_identity_key_id);
CREATE INDEX federation_family_membership_revocations_admitted
    ON federation_family_membership_revocations
       (COALESCE(admitted_at, removed_at), family_key_id, removed_identity_key_id);

-- federation_community_membership_revocations (V071, V130)
CREATE INDEX federation_community_membership_revocations_effective
    ON federation_community_membership_revocations (effective_at);
CREATE INDEX federation_community_membership_revocations_by_member
    ON federation_community_membership_revocations (removed_identity_key_id);
CREATE INDEX federation_community_membership_revocations_admitted
    ON federation_community_membership_revocations
       (COALESCE(admitted_at, removed_at), community_key_id, removed_identity_key_id);

-- federation_location_proofs (V071, V130)
CREATE INDEX federation_location_proofs_by_subject_live
    ON federation_location_proofs (subject_key_id)
    WHERE withdrawn_at IS NULL;
CREATE INDEX federation_location_proofs_by_cell
    ON federation_location_proofs (cell_id);
CREATE INDEX federation_location_proofs_admitted
    ON federation_location_proofs
       (COALESCE(admitted_at, asserted_at), subject_key_id, persist_row_hash);

-- federation_communities (V130)
CREATE INDEX federation_communities_admitted
    ON federation_communities (COALESCE(admitted_at, founded_at), community_key_id);

-- federation_families (V090, V130)
CREATE INDEX federation_families_entrenched
    ON federation_families (family_key_id)
    WHERE consensus_protocol_entrenched = 1;
CREATE INDEX federation_families_admitted
    ON federation_families (COALESCE(admitted_at, founded_at), family_key_id);

-- federation_organizations (V071, V130)
CREATE INDEX federation_organizations_by_org_id
    ON federation_organizations (org_id);
CREATE INDEX federation_organizations_admitted
    ON federation_organizations (COALESCE(admitted_at, asserted_at), attestation_id);

-- federation_org_memberships (V071, V130)
CREATE INDEX federation_org_memberships_by_user_org
    ON federation_org_memberships (user_id, org_id);
CREATE INDEX federation_org_memberships_by_org
    ON federation_org_memberships (org_id);
CREATE INDEX federation_org_memberships_admitted
    ON federation_org_memberships (COALESCE(admitted_at, asserted_at), attestation_id);

-- federation_partner_records (V071, V130)
CREATE INDEX federation_partner_records_by_license_id
    ON federation_partner_records (license_id);
CREATE INDEX federation_partner_records_admitted
    ON federation_partner_records (COALESCE(admitted_at, asserted_at), attestation_id);

-- transport_destinations (V071, V130)
CREATE INDEX transport_destinations_by_occurrence
    ON transport_destinations (occurrence_key_id);
CREATE INDEX transport_destinations_admitted
    ON transport_destinations
       (COALESCE(admitted_at, asserted_at), occurrence_key_id, transport_kind);

-- ══════════════════════════════════════════════════════════════════════════
-- 6. TRIGGERS — the four that lived on the dropped tables, verbatim
-- ══════════════════════════════════════════════════════════════════════════

-- federation_keys (V040 / CIRISPersist#102 Ask 8)
CREATE TRIGGER federation_keys_accord_holder_requires_attestation_insert
BEFORE INSERT ON federation_keys
FOR EACH ROW
WHEN NEW.identity_type = 'accord_holder'
    AND NEW.attestation_evidence IS NULL
BEGIN
    SELECT RAISE(ABORT,
        'federation_keys_accord_holder_requires_attestation: identity_type=accord_holder rows MUST carry attestation_evidence (v2.5.0 / CIRISPersist#102 Ask 8)'
    );
END;

CREATE TRIGGER federation_keys_accord_holder_requires_attestation_update
BEFORE UPDATE OF identity_type, attestation_evidence ON federation_keys
FOR EACH ROW
WHEN NEW.identity_type = 'accord_holder'
    AND NEW.attestation_evidence IS NULL
BEGIN
    SELECT RAISE(ABORT,
        'federation_keys_accord_holder_requires_attestation: identity_type=accord_holder rows MUST carry attestation_evidence (v2.5.0 / CIRISPersist#102 Ask 8)'
    );
END;

-- federation_attestations (V066 / CEG §10.1.5 AV-60)
CREATE TRIGGER federation_attestations_federation_tier_signed_ins
    BEFORE INSERT ON federation_attestations
    FOR EACH ROW
    WHEN (NEW.tier = 'federation' AND NEW.scrub_signature_classical = '')
    BEGIN
        SELECT RAISE(ABORT, 'federation_attestations: tier=federation requires a non-empty scrub_signature_classical (federation ⟹ signed; CEG §10.1.5 AV-60). A deferred-signature row must be tier=local.');
    END;

CREATE TRIGGER federation_attestations_federation_tier_signed_upd
    BEFORE UPDATE ON federation_attestations
    FOR EACH ROW
    WHEN (NEW.tier = 'federation' AND NEW.scrub_signature_classical = '')
    BEGIN
        SELECT RAISE(ABORT, 'federation_attestations: tier=federation requires a non-empty scrub_signature_classical (federation ⟹ signed; CEG §10.1.5 AV-60). A deferred-signature row must be tier=local.');
    END;
