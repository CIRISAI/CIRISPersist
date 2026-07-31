-- V114 — the attested subject may be a KEYLESS constitutional family
-- v24.0.0 (CIRISPersist#557)
--
-- POSTGRES PARITY: migrations/postgres/lens/V114__attested_subject_may_be_a_family.sql
-- (a no-op there: `cirislens.federation_attestations` never declared this FK.
-- The rule now lives in ONE place — the shared admission predicate — and runs
-- identically on all three backends, so postgres GAINS the check it never had
-- while sqlite loses only the schema clause, not the rule.)
--
-- WHAT MOVES, AND WHY IT IS NOT A LOOSENING
-- -----------------------------------------
-- `federation_attestations.attested_key_id` carried
-- `REFERENCES federation_keys(key_id)`. The rule it encodes — "you may not
-- attest ABOUT an identifier this node has never heard of" — is right and is
-- KEPT. What the schema cannot express is the one legitimate exception:
--
--   a CONSTITUTIONAL FAMILY is KEYLESS by doctrine (v13.3.0 dropped
--   `families.family_key_id`'s FK for exactly this reason — the family id is
--   an identifier, not a key; there is no seat to compromise, which is
--   precisely why it can be the durable name of a trust root).
--
-- #557's whole ask is that a node's `trust:accepts` edge NAME THE ACCORD
-- rather than whichever holder happened to sign the charter — i.e.
-- `delegates_to(node → humanity-accord)`, plus the family's charter and drill
-- rows. Every one of those has `attested_key_id = <family id>`, and a keyless
-- family has no `federation_keys` row to point at. Under this FK the family
-- root is not merely unimplemented, it is UNSTORABLE.
--
-- So the constraint is not deleted — it is LIFTED into
-- `check_attested_subject_admission` (src/federation/admission.rs), which
-- refuses any `attested_key_id` that resolves as NEITHER a registered
-- `federation_keys` row NOR a constitutional family this node already knows.
-- That is strictly narrower than "any string" and, unlike the FK, it is the
-- same predicate on memory, sqlite and postgres.
--
-- HOW (the SQLite table-rebuild recipe, done safely)
-- -------------------------------------------------
-- SQLite has no `ALTER TABLE ... DROP CONSTRAINT`, so the table is rebuilt.
-- Two tables carry FKs INTO `federation_attestations(attestation_id)`:
--   * `attestation_subjects.attestation_id`            ON DELETE CASCADE (V106)
--   * `identity_canonical_binding.binding_attestation_id` ON DELETE SET NULL (V056)
-- With `PRAGMA foreign_keys = ON` (set at every connection open) a `DROP TABLE`
-- performs an implicit `DELETE FROM` that FIRES those actions — it would wipe
-- the subject projection and null the canonical bindings. `PRAGMA` statements
-- are no-ops inside refinery's per-migration transaction, so turning FKs off is
-- not available. The rows are therefore STAGED before the drop and restored
-- after, inside the same transaction: nothing observable changes but the schema.
--
-- The FKs on `attesting_key_id` and `scrub_key_id` are DELIBERATELY KEPT: those
-- two identify SIGNERS, and a signer with no key record could not have signed.
-- Only the attested SUBJECT gains the family exception.

-- ── 1. stage everything the implicit delete would touch ────────────
CREATE TABLE _v114_stage_fa AS
    SELECT attestation_id, attesting_key_id, attested_key_id, attestation_type,
           weight, asserted_at, expires_at, attestation_envelope,
           original_content_hash, scrub_signature_classical, scrub_signature_pqc,
           scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash,
           subject_key_ids, withdraws_admission_rule, cohort_scope, tier,
           promoted_at, additional_scrubs
    FROM federation_attestations;

CREATE TABLE _v114_stage_subjects AS
    SELECT subject_key_id, dimension, asserted_at, attestation_id, tier, cohort_scope
    FROM attestation_subjects;

CREATE TABLE _v114_stage_binding AS
    SELECT canonical_hash, binding_attestation_id
    FROM identity_canonical_binding
    WHERE binding_attestation_id IS NOT NULL;

-- ── 2. swap in the rebuilt parent ──────────────────────────────────
-- Identical to the V004+V055+V056+V066+V106+V113 accumulated shape, MINUS the
-- `attested_key_id` REFERENCES clause. Every CHECK is reproduced verbatim
-- (including `withdraws_admission_rule BETWEEN 1 AND 4`, which V055 wrote and
-- which this migration deliberately does not silently widen).
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
    withdraws_admission_rule   INTEGER
        CHECK (withdraws_admission_rule IS NULL
               OR withdraws_admission_rule BETWEEN 1 AND 4),
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
FROM _v114_stage_fa;

-- ── 3. restore the children the drop cascaded / nulled ─────────────
DELETE FROM attestation_subjects;
INSERT INTO attestation_subjects
    (subject_key_id, dimension, asserted_at, attestation_id, tier, cohort_scope)
SELECT subject_key_id, dimension, asserted_at, attestation_id, tier, cohort_scope
FROM _v114_stage_subjects;

UPDATE identity_canonical_binding
   SET binding_attestation_id = (
        SELECT s.binding_attestation_id
        FROM _v114_stage_binding s
        WHERE s.canonical_hash = identity_canonical_binding.canonical_hash)
 WHERE canonical_hash IN (SELECT canonical_hash FROM _v114_stage_binding);

DROP TABLE _v114_stage_fa;
DROP TABLE _v114_stage_subjects;
DROP TABLE _v114_stage_binding;

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
