-- V150 — the ROW's cohort target, as a generated column
-- v46.5.0 (CIRISPersist#893)
--
-- SQLITE PARITY: migrations/sqlite/lens/V150__cohort_target_generated_column.sql
--
-- # Why
--
-- AV-84 (#592) makes a `community` / `family` row name its own PRODUCER in
-- `attested_key_id`; the §4.3 read gate compared that column against the
-- caller's admitted room set. The intersection is empty by construction, so
-- no member could read their own room's rows. The gate has to ask the ROW's
-- room — the predicate persist's own hold path and edge's serve gate already
-- use — and the row states it in its SIGNED envelope.
--
-- `federation_attestations` had no column for it (`cohort_target_id` is a
-- `trace_events` column, V060), which is why the hole survived: the only
-- community round-trip test is on the trace plane, which has one.
--
-- # Why GENERATED, and why COALESCE
--
-- Generated from `attestation_envelope` — the V106 `dimension` precedent —
-- so the value a read keys on cannot drift from the value the write gate
-- validated. No backfill and no row rewrite: the column is computed.
--
-- The alias order is `admission::COHORT_TARGET_ENVELOPE_FIELDS` verbatim.
-- `envelope_cohort_target` REFUSES a split-brain row (two populated aliases
-- that disagree, PR #759 review) at the put, promote and re-scope doors, so
-- every STORED row has agreeing aliases and a COALESCE over them is total —
-- it picks the one value the row carries, whichever alias spells it.
--
-- STORED on postgres: a generated column there must be STORED, and the
-- rewrite is one pass over a table this migration is the only writer of.
-- (sqlite takes VIRTUAL; see the parity file.)

ALTER TABLE cirislens.federation_attestations
    ADD COLUMN cohort_target TEXT
        GENERATED ALWAYS AS (
            COALESCE(
                (attestation_envelope::jsonb)->>'community_id',
                (attestation_envelope::jsonb)->>'community_key_id',
                (attestation_envelope::jsonb)->>'cohort_key_id',
                (attestation_envelope::jsonb)->>'family_key_id'
            )
        ) STORED;

-- A FUTURE REBUILD MUST CARRY THIS. If a later migration transcribes
-- cirislens.federation_attestations into a `_new` table and renames (the V141 shape,
-- CIRISPersist#828), it has to re-create BOTH the generated column and the
-- index below, or the targeted read gate silently refuses every row again.
-- `v141_rebuild_backfills_...` is the witness for that class.

-- The targeted arms seek (cohort_scope, cohort_target); the broad tiers and
-- `self` never touch this column. Partial on the two scopes that use it, for
-- the same reason V056's cohort_scope index is partial.
CREATE INDEX IF NOT EXISTS federation_attestations_cohort_target
    ON cirislens.federation_attestations (cohort_scope, cohort_target)
    WHERE cohort_scope IN ('community', 'affiliations', 'family');
