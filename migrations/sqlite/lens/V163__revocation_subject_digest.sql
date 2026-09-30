-- V163 (v52.0.0, CIRISPersist#784) — a revocation names its subject by the
-- SHA-256 of the key's RAW Ed25519 public key, not by its `key_id`.
--
-- A `key_id` is `<label>-<fingerprint>`, the label in cleartext, so a
-- revocation that names one publishes the subject's keystore label to every
-- node it reaches. From v52 the subject is `revoked_key_sha256_ed25519_raw`
-- (64 lowercase hex, bound into the signed envelope); `revoked_key_id` is an
-- optional second name, checked against the digest at admission.
--
-- Two shape changes, so the table is rebuilt:
--   * `revoked_key_id` becomes NULLable and loses its FK to federation_keys:
--     a digest-only revocation may precede the key record (#784 D1), which
--     deliberately relaxes V004's "cannot revoke a key not in the directory".
--   * `revoked_key_sha256_ed25519_raw` is added. SQLite has no SHA-256, so
--     this file cannot compute it for existing rows: the column is NULLable
--     here and `SqliteBackend::backfill_revocation_subject_digests` fills it
--     at open, before any read, and REFUSES the open if a row stays NULL.
--     Every insert stamps it.
--
-- Rebuilt under its final name with the drop made inert (the V141 recipe):
-- `federation_revocation_quorum_state` CASCADEs from this table, so it is
-- staged and emptied first, the table is dropped empty, re-created, and both
-- are restored parent-first. Explicit column lists throughout.

PRAGMA defer_foreign_keys = ON;

CREATE TABLE _v163_stage_revocations AS
    SELECT revocation_id, revoked_key_id, revoking_key_id, reason, revoked_at,
           effective_at, revocation_envelope, original_content_hash,
           scrub_signature_classical, scrub_signature_pqc, scrub_key_id,
           scrub_timestamp, pqc_completed_at, persist_row_hash,
           observed_region, revoked_after, admitted_at
    FROM federation_revocations;

CREATE TABLE _v163_stage_revocation_quorum_state AS
    SELECT revocation_id, us_observed_at, eu_observed_at, apac_observed_at,
           quorum_reached_at, quorum_weight, updated_at
    FROM federation_revocation_quorum_state;

DELETE FROM federation_revocation_quorum_state;
DELETE FROM federation_revocations;

DROP TABLE federation_revocations;
CREATE TABLE federation_revocations (
    revocation_id         TEXT PRIMARY KEY,
    revoked_key_id        TEXT,
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
    admitted_at                TEXT NOT NULL,
    revoked_key_sha256_ed25519_raw TEXT
        CHECK (revoked_key_sha256_ed25519_raw IS NULL
               OR (length(revoked_key_sha256_ed25519_raw) = 64
                   AND revoked_key_sha256_ed25519_raw NOT GLOB '*[^0-9a-f]*'))
);

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
FROM _v163_stage_revocations;

INSERT INTO federation_revocation_quorum_state
    (revocation_id, us_observed_at, eu_observed_at, apac_observed_at,
     quorum_reached_at, quorum_weight, updated_at)
SELECT revocation_id, us_observed_at, eu_observed_at, apac_observed_at,
       quorum_reached_at, quorum_weight, updated_at
FROM _v163_stage_revocation_quorum_state;

DROP TABLE _v163_stage_revocation_quorum_state;
DROP TABLE _v163_stage_revocations;

-- Readers key on the digest (#784); the key_id index stays for the optional
-- second name.
CREATE INDEX federation_revocations_subject
    ON federation_revocations (revoked_key_sha256_ed25519_raw, effective_at DESC);
CREATE INDEX federation_revocations_revoked
    ON federation_revocations (revoked_key_id, effective_at DESC);
CREATE INDEX federation_revocations_observed_region
    ON federation_revocations (observed_region, revoked_key_sha256_ed25519_raw, scrub_timestamp DESC)
    WHERE observed_region != 'us';
CREATE INDEX federation_revocations_admitted
    ON federation_revocations (COALESCE(admitted_at, scrub_timestamp), revocation_id);
