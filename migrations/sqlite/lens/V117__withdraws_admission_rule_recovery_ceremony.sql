-- V117 — admit rule 5, the CC 3.2 ownerless-lock RECOVERY CEREMONY, into
-- federation_attestations.withdraws_admission_rule — SQLite dialect
-- v25.x (CIRISPersist#578, CIRISConstitution rc3 CC 3.2)
--
-- POSTGRES PARITY: migrations/postgres/lens/V117__withdraws_admission_rule_recovery_ceremony.sql
-- (same widening; Postgres has DROP CONSTRAINT so its twin is a discovery-drop
-- plus a re-add, and this one is a table rebuild. Same rationale, below.)
--
-- WHAT THIS FIXES — AND IT IS NOT ONLY A NEW RULE NUMBER
-- -----------------------------------------------------
-- V055 wrote `withdraws_admission_rule BETWEEN 1 AND 4` because CEG §3.2.3 had
-- exactly four admission rules. v21.8.0 then added a FIFTH — the ownerless-lock
-- reclaim exception — and stamped `withdraws_admission_rule = 5` on the rows it
-- admitted. That value has never been storable on sqlite or postgres: the CHECK
-- refuses it, so the write fails at INSERT with a constraint violation.
--
-- The memory backend has no CHECK and accepted it happily, which is exactly why
-- nothing caught this for four minor versions: the mechanism was declared
-- ACTIVATED, its unit tests called the gate function directly and never stored a
-- row, and the one backend that could store it was the one that enforces
-- nothing. The recurring class — a feature certified done while no real host
-- could reach it. #578's ceremony witness stores the gated `withdraws` through
-- the REAL `put_attestation` path on all three backends, which is what surfaced
-- it on the first run.
--
-- WHAT RULE 5 MEANS NOW
-- ---------------------
-- rc3 re-points the recovery path: the gated `withdraws` must carry a
-- `wa_adjudication_ref` naming a CC 4.3 Wise-Authority quorum finding of
-- abandonment or seizure, filed by an issuer with CC 2.4.1.1 rule-(2)/(4)
-- standing, after which the node is UNOWNED until a fresh owner-binding
-- co-signed by the node itself lands. Rule 5 is the audit stamp that records
-- "this withdraws was admitted by the recovery ceremony, not by one of the four
-- ordinary rules" — and `check_post_reclaim_rebinding_admission` reads it back
-- off this very column to know the node owes that co-signature. So the value
-- being storable is load-bearing twice: once as audit, once as state.
--
-- The range stays CLOSED at 5. A sixth rule must widen it deliberately, in a
-- migration, on both backends — which is the property V055 was reaching for and
-- which this preserves rather than replacing with an open integer.
--
-- HOW (the SQLite table-rebuild recipe, done safely)
-- -------------------------------------------------
-- SQLite bakes table-level CHECKs into CREATE TABLE and has no
-- `ALTER TABLE ... DROP CONSTRAINT`, so the table is rebuilt — the V020 / V035 /
-- V061 / V097 / V114 / V115 / V116 recipe, and specifically V114's, since that
-- migration rebuilt THIS table and its comment noted it "deliberately does not
-- silently widen" this CHECK. This one widens it deliberately.
--
-- Two tables carry FKs INTO `federation_attestations(attestation_id)`:
--   * `attestation_subjects.attestation_id`               ON DELETE CASCADE (V106)
--   * `identity_canonical_binding.binding_attestation_id` ON DELETE SET NULL (V056)
-- With `PRAGMA foreign_keys = ON` (set at every connection open) a `DROP TABLE`
-- performs an implicit `DELETE FROM` that FIRES those actions. `PRAGMA` is a
-- no-op inside refinery's per-migration transaction, so the rows are STAGED
-- before the drop and restored after, inside the same transaction — V114's
-- procedure, unchanged, because the failure mode it guards against (a silent
-- wipe of the subject projection) is unchanged.
--
-- Every other CHECK, index, trigger, default and NULL-ability is reproduced
-- verbatim from the V004+V055+V056+V066+V106+V113+V114 accumulated shape. A
-- rebuild is the moment a constraint is silently lost, so the whole intended
-- diff is the single `BETWEEN 1 AND 4` → `BETWEEN 1 AND 5`.

-- ── 1. stage everything the implicit delete would touch ────────────
CREATE TABLE _v117_stage_fa AS
    SELECT attestation_id, attesting_key_id, attested_key_id, attestation_type,
           weight, asserted_at, expires_at, attestation_envelope,
           original_content_hash, scrub_signature_classical, scrub_signature_pqc,
           scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash,
           subject_key_ids, withdraws_admission_rule, cohort_scope, tier,
           promoted_at, additional_scrubs
    FROM federation_attestations;

CREATE TABLE _v117_stage_subjects AS
    SELECT subject_key_id, dimension, asserted_at, attestation_id, tier, cohort_scope
    FROM attestation_subjects;

CREATE TABLE _v117_stage_binding AS
    SELECT canonical_hash, binding_attestation_id
    FROM identity_canonical_binding
    WHERE binding_attestation_id IS NOT NULL;

-- ── 2. swap in the rebuilt parent ──────────────────────────────────
DROP TABLE federation_attestations;

CREATE TABLE federation_attestations (
    attestation_id        TEXT PRIMARY KEY,  -- UUID-as-TEXT; caller generates
    attesting_key_id      TEXT NOT NULL REFERENCES federation_keys(key_id),
    -- v24.0.0 (CIRISPersist#557) — NO FK: the attested subject may be a
    -- keyless constitutional family id. Enforced by
    -- `check_attested_subject_admission` on all three backends.
    attested_key_id       TEXT NOT NULL,
    attestation_type      TEXT NOT NULL,
    weight                REAL,
    asserted_at           TEXT NOT NULL,
    expires_at            TEXT,
    attestation_envelope  TEXT NOT NULL,

    original_content_hash      BLOB NOT NULL,
    scrub_signature_classical  TEXT NOT NULL,
    scrub_signature_pqc        TEXT,            -- NULL = hybrid-pending
    scrub_key_id               TEXT NOT NULL REFERENCES federation_keys(key_id),
    scrub_timestamp            TEXT NOT NULL,
    pqc_completed_at           TEXT,

    persist_row_hash           TEXT NOT NULL,

    subject_key_ids            TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(subject_key_ids)
               AND json_type(subject_key_ids) = 'array'),
    -- v25.x (CIRISPersist#578) — 5 is the CC 3.2 recovery ceremony. Closed
    -- range: a sixth rule widens this deliberately, on both backends.
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
        GENERATED ALWAYS AS (json_extract(attestation_envelope, '$.dimension')) VIRTUAL
);

INSERT INTO federation_attestations (
    attestation_id, attesting_key_id, attested_key_id, attestation_type,
    weight, asserted_at, expires_at, attestation_envelope,
    original_content_hash, scrub_signature_classical, scrub_signature_pqc,
    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash,
    subject_key_ids, withdraws_admission_rule, cohort_scope, tier,
    promoted_at, additional_scrubs)
SELECT
    attestation_id, attesting_key_id, attested_key_id, attestation_type,
    weight, asserted_at, expires_at, attestation_envelope,
    original_content_hash, scrub_signature_classical, scrub_signature_pqc,
    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash,
    subject_key_ids, withdraws_admission_rule, cohort_scope, tier,
    promoted_at, additional_scrubs
FROM _v117_stage_fa;

-- ── 3. restore the children the drop cascaded / nulled ─────────────
DELETE FROM attestation_subjects;
INSERT INTO attestation_subjects
    (subject_key_id, dimension, asserted_at, attestation_id, tier, cohort_scope)
SELECT subject_key_id, dimension, asserted_at, attestation_id, tier, cohort_scope
FROM _v117_stage_subjects;

UPDATE identity_canonical_binding
   SET binding_attestation_id = (
        SELECT s.binding_attestation_id
        FROM _v117_stage_binding s
        WHERE s.canonical_hash = identity_canonical_binding.canonical_hash)
 WHERE canonical_hash IN (SELECT canonical_hash FROM _v117_stage_binding);

DROP TABLE _v117_stage_fa;
DROP TABLE _v117_stage_subjects;
DROP TABLE _v117_stage_binding;

-- ── 4. every index + trigger the dropped table carried ─────────────
-- V004
CREATE INDEX IF NOT EXISTS federation_attestations_attested
    ON federation_attestations (attested_key_id, asserted_at DESC);
CREATE INDEX IF NOT EXISTS federation_attestations_attesting
    ON federation_attestations (attesting_key_id, asserted_at DESC);
-- V055
CREATE INDEX IF NOT EXISTS federation_attestations_withdraws_admission_rule_idx
    ON federation_attestations (withdraws_admission_rule)
    WHERE withdraws_admission_rule IS NOT NULL;
-- V056
CREATE INDEX IF NOT EXISTS federation_attestations_cohort_scope
    ON federation_attestations (cohort_scope)
    WHERE cohort_scope != 'federation';
-- V060
CREATE INDEX IF NOT EXISTS idx_federation_attestations_v060_by_target
    ON federation_attestations (attested_key_id, cohort_scope, asserted_at DESC);
CREATE INDEX IF NOT EXISTS idx_federation_attestations_v060_emitter_scope
    ON federation_attestations (scrub_key_id, cohort_scope);
-- V066
CREATE INDEX IF NOT EXISTS federation_attestations_local_tier
    ON federation_attestations (tier)
    WHERE tier = 'local';
-- V107
CREATE INDEX IF NOT EXISTS federation_attestations_composer_ref
    ON federation_attestations (
        attesting_key_id,
        attestation_type,
        json_extract(attestation_envelope, '$.references_attestation_id')
    );

-- V066 — federation ⟹ non-empty classical signature (AV-60).
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
