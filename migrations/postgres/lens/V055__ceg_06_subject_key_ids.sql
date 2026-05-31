-- V055 — CEG 0.6 subject_key_ids[] on federation_attestations
--        (CIRISPersist#146, v3.7.0).
--
-- # What CEG 0.6 added
--
-- CEG 0.6 landed at CIRISRegistry on 2026-05-31 (commit d8b53a0); see
-- FSD/CEG/04_envelope.md §4.2 for the full envelope spec. The missing
-- half of consent at the wire format: CEG ≤0.5 encoded only
-- PRODUCER authority (`attesting_key_id`); CEG 0.6 adds SUBJECT
-- authority for content where the subject of the data is not the
-- producer of the data.
--
-- The §4.2 envelope addition is exactly one OPTIONAL field on the
-- attestation envelope:
--
--   subject_key_ids: list of consent-holder key_ids for this
--                    attestation. Each entry MAY be either:
--                      (1) a federation_keys.key_id (federation-
--                          enrolled subject; signs on its own behalf), OR
--                      (2) a canonical-hash identifier (external party
--                          with no federation_keys row — Discord user-id,
--                          channel-id, etc.; revocation rides delegates_to)
--                    Default null/[] = status quo (producer-only authority).
--
-- # Why this is additive (1+4 wire-format lockdown preserved)
--
-- Per CEG §3 1+4 wire-format lockdown: no new attestation_type. The
-- field is on the envelope; the wire-format `scores` workhorse +
-- 4 structural composers (delegates_to, supersedes, withdraws, recants)
-- are unchanged. CEG 0.6 broadens the *admission rule* for `withdraws`
-- (CEG §3.2.3) — the substrate now admits a withdraws against target T
-- when the issuer satisfies ANY of:
--
--   1. issuer.key_id == T.attesting_key_id              (today's shape)
--   2. issuer.key_id ∈ T.subject_key_ids                (CEG 0.6 NEW)
--   3. ∃ delegates_to chain: issuer →* canonical_hash   (CEG 0.6 NEW)
--      where canonical_hash ∈ T.subject_key_ids
--   4. issuer holds valid delegates_to → any of 1-3     (existing delegation)
--
-- v3.7.0 lands the schema + persistence; the admission-rule gate
-- itself lands in v3.8.0 alongside `consent_record` subject_kind
-- admission (CIRISPersist#146 Ask 5).
--
-- # Per-rule audit metadata
--
-- §3.2.3 also says the substrate SHOULD record which of the 4 rules
-- admitted each `withdraws` so consumers can compose policy by rule
-- (e.g., subject self-revocation rule 2 weighted higher than proxy
-- rule 3). The `withdraws_admission_rule` column carries this.
-- NULL on non-withdraws rows; SMALLINT 1-4 on withdraws.
--
-- # Default-empty discipline
--
-- Per CEG §4.2.5: `subject_key_ids: null` or `[]` is the status-quo
-- shape; all CEG 0.x consumers that don't read the field see status-
-- quo behavior. We default to `'[]'::jsonb` (NOT NULL) so consumers
-- never see NULL — only the empty-list marker.

ALTER TABLE cirislens.federation_attestations
    ADD COLUMN IF NOT EXISTS subject_key_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS withdraws_admission_rule SMALLINT NULL;

-- The withdraws_admission_rule CHECK: 1-4 when populated, NULL on
-- non-withdraws rows. Mirrors V054's CHECK discipline.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'federation_attestations_withdraws_admission_rule_range'
          AND conrelid = 'cirislens.federation_attestations'::regclass
    ) THEN
        ALTER TABLE cirislens.federation_attestations
            ADD CONSTRAINT federation_attestations_withdraws_admission_rule_range
                CHECK (withdraws_admission_rule IS NULL
                       OR withdraws_admission_rule BETWEEN 1 AND 4);
    END IF;
END$$;

-- The subject_key_ids array-shape CHECK: must be a JSON array (not
-- object, not string, not number). JSONB '[]' satisfies this; so does
-- any non-empty array. The check kicks in if a writer attempts to
-- store a malformed value via direct SQL.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'federation_attestations_subject_key_ids_is_array'
          AND conrelid = 'cirislens.federation_attestations'::regclass
    ) THEN
        ALTER TABLE cirislens.federation_attestations
            ADD CONSTRAINT federation_attestations_subject_key_ids_is_array
                CHECK (jsonb_typeof(subject_key_ids) = 'array');
    END IF;
END$$;

-- GIN index on subject_key_ids supports the §10.1.3 read accessor
-- `list_attestations_for_subject(subject_key_id, filter)` via the
-- JSONB containment operator `?` or `@>`. Pay zero overhead for
-- empty-array (status-quo) rows because GIN compresses empty entries.
CREATE INDEX IF NOT EXISTS federation_attestations_subject_key_ids_gin
    ON cirislens.federation_attestations USING GIN (subject_key_ids);

-- Partial index on withdraws_admission_rule for audit-by-rule queries.
-- The non-withdraws case (vast majority of rows) pays zero overhead.
CREATE INDEX IF NOT EXISTS federation_attestations_withdraws_admission_rule_idx
    ON cirislens.federation_attestations (withdraws_admission_rule)
    WHERE withdraws_admission_rule IS NOT NULL;

COMMENT ON COLUMN cirislens.federation_attestations.subject_key_ids IS
    'v3.7.0 (CIRISPersist#146, CEG 0.6 §4.2). OPTIONAL list of consent-holder key_ids for this attestation. Each entry MAY be a federation_keys.key_id OR a canonical-hash identifier (CEG 0.6 §4.2.2). Default [] = status quo (producer-only authority). Substrate does NOT FK-enforce that entries are federation_keys rows — canonical-hash subjects (Discord user-ids, external party identifiers) are valid per CEG 0.6 design.';

COMMENT ON COLUMN cirislens.federation_attestations.withdraws_admission_rule IS
    'v3.7.0 (CIRISPersist#146, CEG 0.6 §3.2.3). Per-rule audit metadata: which of the 4 admission rules admitted this withdraws. 1 = producer self-revocation (legacy), 2 = subject self-revocation (CEG 0.6 NEW), 3 = delegates_to proxy with consent_revocation scope (CEG 0.6 NEW), 4 = delegates_to chain via any of 1-3. NULL on non-withdraws rows. Populated at admission time in v3.8.0+ once the 4-rule admission gate lands.';
