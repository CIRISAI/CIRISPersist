-- V106 — CIRISPersist#454 (FSD-005 Appendix C): the durable `scores` read
--        surface. SQLite dialect. Postgres parity: postgres/lens/V106.
--
-- Ships the (B) normalized subject-index projection chosen in Appendix C.1:
-- one `attestation_subjects` row per (attestation, subject_key_ids[] element),
-- maintained on every attestation write + a one-time backfill. The hot query
-- "subject X, dimension D, newest-first" becomes an index-only ordered seek —
-- identical btree on BOTH backends (the #442 divergence class is what a
-- Postgres-only GIN-on-expression would have reopened).
--
-- Three parts:
--   1. a generated `dimension` column on federation_attestations (the exact-
--      match + prefix axis, materialized once instead of json_extract per row);
--   2. the `attestation_subjects` projection table + its ordered-seek index;
--   3. the backfill from existing rows.
--
-- Backend ASYMMETRY (documented): SQLite cannot `ALTER TABLE ... ADD COLUMN`
-- a STORED generated column — only VIRTUAL is permitted for ADD COLUMN — so
-- the SQLite `dimension` column is VIRTUAL (recomputed at read) where Postgres
-- uses STORED. The projection table's `dimension` column is a PLAIN column
-- (populated at maintenance time), identical on both backends. The Postgres-
-- only GIN on `evidence_refs` (citation lookup) has no SQLite analogue —
-- SQLite falls to a json scan for that path, which is out of the v17.4.0 hot
-- set.

-- ── 1. generated dimension column ──────────────────────────────────
-- VIRTUAL (SQLite ADD COLUMN cannot be STORED); Postgres parity is STORED.
ALTER TABLE federation_attestations
    ADD COLUMN dimension TEXT
        GENERATED ALWAYS AS (json_extract(attestation_envelope, '$.dimension')) VIRTUAL;

-- ── 2. attestation_subjects projection ─────────────────────────────
-- One row per (attestation, subject_key_ids[] element). `dimension`,
-- `tier`, `cohort_scope` are denormalized copies of the parent row's values
-- at maintenance time (kept in sync by the write-path hooks + promote). The
-- FK ON DELETE CASCADE drops projection rows when the parent attestation is
-- hard-deleted (the reader never sees an orphaned subject index entry).
CREATE TABLE attestation_subjects (
    subject_key_id  TEXT NOT NULL,
    dimension       TEXT,                    -- NULL iff the envelope has no dimension
    asserted_at     TEXT NOT NULL,           -- RFC-3339 UTC, copy of parent
    attestation_id  TEXT NOT NULL
        REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE,
    tier            TEXT NOT NULL,           -- 'local' | 'federation', copy of parent
    cohort_scope    TEXT NOT NULL,           -- copy of parent (the §4.3 gate axis)
    PRIMARY KEY (subject_key_id, attestation_id)
);

-- The ordered seek: (subject_key_id, dimension, asserted_at DESC, attestation_id).
-- Serves list_scores' "subject X, dimension D, newest-first" as an index-only
-- range scan and the (asserted_at, attestation_id) cursor tiebreak.
CREATE INDEX attestation_subjects_seek
    ON attestation_subjects (subject_key_id, dimension, asserted_at DESC, attestation_id);

-- ── 3. backfill ────────────────────────────────────────────────────
-- Expand each existing row's subject_key_ids[] into one projection row per
-- element. Empty-array rows emit nothing (json_each yields no rows), so they
-- pay zero cost — they are simply not subject-indexed (correct: a scores read
-- is subject-keyed).
INSERT INTO attestation_subjects
    (subject_key_id, dimension, asserted_at, attestation_id, tier, cohort_scope)
SELECT
    je.value,
    json_extract(fa.attestation_envelope, '$.dimension'),
    fa.asserted_at,
    fa.attestation_id,
    fa.tier,
    fa.cohort_scope
FROM federation_attestations fa,
     json_each(fa.subject_key_ids) je;
