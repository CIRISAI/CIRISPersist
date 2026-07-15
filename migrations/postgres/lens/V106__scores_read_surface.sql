-- V106 — CIRISPersist#454 (FSD-005 Appendix C): the durable `scores` read
--        surface. Postgres dialect. SQLite parity: sqlite/lens/V106.
--
-- Ships the (B) normalized subject-index projection chosen in Appendix C.1:
-- one `cirislens.attestation_subjects` row per (attestation, subject_key_ids[]
-- element), maintained on every attestation write + a one-time backfill. The
-- hot query "subject X, dimension D, newest-first" becomes an index-only
-- ordered seek — IDENTICAL btree on both backends (rejecting a Postgres-only
-- GIN-on-expression, which cannot give an ordered subject+dimension seek and
-- would reopen the #442 two-code-path divergence).
--
-- Backend ASYMMETRY (documented): the `dimension` generated column is STORED
-- here (Postgres permits it on ADD COLUMN); SQLite's ADD COLUMN allows VIRTUAL
-- only. The Postgres-only GIN on `evidence_refs` (the citation lookup)
-- accelerates evidence-graph reads; SQLite has no analogue.

-- ── 1. generated dimension column (STORED) ─────────────────────────
ALTER TABLE cirislens.federation_attestations
    ADD COLUMN dimension TEXT
        GENERATED ALWAYS AS (attestation_envelope->>'dimension') STORED;

-- ── 2. attestation_subjects projection ─────────────────────────────
-- One row per (attestation, subject_key_ids[] element). dimension/tier/
-- cohort_scope are denormalized copies of the parent row, kept in sync by the
-- write-path hooks + promote. FK ON DELETE CASCADE drops projection rows on a
-- parent hard-delete.
CREATE TABLE cirislens.attestation_subjects (
    subject_key_id  TEXT NOT NULL,
    dimension       TEXT,
    asserted_at     TIMESTAMPTZ NOT NULL,
    attestation_id  UUID NOT NULL
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE,
    tier            TEXT NOT NULL,
    cohort_scope    TEXT NOT NULL,
    PRIMARY KEY (subject_key_id, attestation_id)
);

-- The ordered seek: (subject_key_id, dimension, asserted_at DESC, attestation_id).
CREATE INDEX attestation_subjects_seek
    ON cirislens.attestation_subjects (subject_key_id, dimension, asserted_at DESC, attestation_id);

-- ── 3. GIN on evidence_refs (Postgres-only) ────────────────────────
-- The citation lookup — "which attestations cite evidence E" — over the
-- envelope's evidence_refs array. SQLite skips this (json scan; out of the
-- v17.4.0 hot set).
CREATE INDEX federation_attestations_evidence_refs_gin
    ON cirislens.federation_attestations
    USING GIN ((attestation_envelope->'evidence_refs'));

-- ── 4. backfill ────────────────────────────────────────────────────
-- Expand each existing row's subject_key_ids[] into one projection row per
-- element. Empty arrays emit nothing (LATERAL yields no rows) — subject-keyed
-- by construction, so empty-subject rows are correctly not indexed.
INSERT INTO cirislens.attestation_subjects
    (subject_key_id, dimension, asserted_at, attestation_id, tier, cohort_scope)
SELECT
    elem,
    fa.attestation_envelope->>'dimension',
    fa.asserted_at,
    fa.attestation_id,
    fa.tier,
    fa.cohort_scope
FROM cirislens.federation_attestations fa,
     LATERAL jsonb_array_elements_text(fa.subject_key_ids) AS elem;
