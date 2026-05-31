-- V055 — CEG 0.6 subject_key_ids[] on federation_attestations, SQLite
--        dialect (CIRISPersist#146, v3.7.0).
--
-- Postgres parity (postgres/lens/V055):
--   - federation_attestations gains subject_key_ids JSONB NOT NULL
--     DEFAULT '[]'::jsonb (Postgres) / TEXT NOT NULL DEFAULT '[]' (SQLite,
--     JSON-as-TEXT per the json1 extension convention; jsonb at use
--     time via json() / json_each()).
--   - federation_attestations gains withdraws_admission_rule SMALLINT
--     (Postgres) / INTEGER (SQLite), NULL on non-withdraws rows.
--   - Postgres CHECK constraints land here as BEFORE INSERT/UPDATE
--     triggers (SQLite has no ALTER TABLE … ADD CONSTRAINT). Matches
--     V054's discipline.
--   - GIN index on subject_key_ids is a Postgres-only optimization;
--     SQLite uses json_each() at query time for the lookup. The
--     federation_attestations_subject_lookup expression index below
--     covers the common any-subject case.
--
-- See migrations/postgres/lens/V055 for the full design rationale.

ALTER TABLE federation_attestations
    ADD COLUMN subject_key_ids TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(subject_key_ids)
               AND json_type(subject_key_ids) = 'array');

ALTER TABLE federation_attestations
    ADD COLUMN withdraws_admission_rule INTEGER
        CHECK (withdraws_admission_rule IS NULL
               OR withdraws_admission_rule BETWEEN 1 AND 4);

-- Partial index on withdraws_admission_rule for audit-by-rule queries.
CREATE INDEX IF NOT EXISTS federation_attestations_withdraws_admission_rule_idx
    ON federation_attestations (withdraws_admission_rule)
    WHERE withdraws_admission_rule IS NOT NULL;

-- Expression index supporting the §10.1.3 read accessor
-- `list_attestations_for_subject(subject_key_id)`. SQLite json1 admits
-- expression indexes on json_each-style decompositions, but the
-- canonical pattern is a generated column we can index. For the v3.7.0
-- foundation cut we leave the raw query path (json_each at SELECT
-- time); v3.8.0 adds a virtual-table or generated-column index if the
-- benchmark calls for it.
--
-- Empty-array rows pay zero index overhead because json_each emits no
-- rows for an empty array — meaning the index above is naturally
-- sparse without an explicit WHERE clause.
