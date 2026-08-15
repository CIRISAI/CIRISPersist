-- V127 — scrub TREATMENT columns (v32.0.0, CIRISPersist#690, PostgreSQL).
--
-- Mirrored by migrations/sqlite/lens/V127__scrub_treatment_columns.sql.
--
-- These are not metadata beside the scrub envelope. #690 widened
-- `scrub_signature` from `sign(canonical(data_post_scrub))` to a signature over
-- the whole envelope, and these three values are INSIDE that preimage. Without
-- these columns a verifier cannot rebuild the preimage, so it cannot check the
-- signature at all — the claim would be signed and permanently unverifiable,
-- which is worse than the ambiguity #690 set out to remove.
--
--   * scrub_ner_ran               did a named-entity pass actually run?
--   * scrub_applied_trace_level   the level the content was TREATED at, which
--                                 may be a downgrade from its label
--   * scrub_model_digest          which model ran; NULL when none did
--
-- NULLABLE, and that is deliberate: pre-v32.0.0 rows carry signatures over the
-- older, narrower preimage and have no claim to record. `scrub_ner_ran IS NULL`
-- is the discriminator — a v32.0.0 row that honestly ran no NER pass writes
-- FALSE, not NULL, so "no claim was made" and "a claim of no pass" stay
-- distinct. A verifier that conflated them would accept an unscrubbed row as
-- attested.
--
-- Unlike V126 on this dialect, these do NOT become NOT NULL: pre-v32.0.0 rows
-- legitimately have no claim, so there is nothing to backfill them with.
-- Inventing FALSE would assert that those rows were checked and found to have
-- had no NER pass, when nothing was ever recorded either way — the exact
-- synthesis of evidence this codebase refuses elsewhere.

ALTER TABLE cirislens.trace_events ADD COLUMN IF NOT EXISTS scrub_ner_ran             BOOLEAN;
ALTER TABLE cirislens.trace_events ADD COLUMN IF NOT EXISTS scrub_applied_trace_level TEXT;
ALTER TABLE cirislens.trace_events ADD COLUMN IF NOT EXISTS scrub_model_digest        TEXT;

-- The enforcement query this exists to serve: "every full_traces row whose
-- model digest is not on my accept-list". Partial, because rows without a
-- treatment claim are not candidates and should not be paged through.
CREATE INDEX IF NOT EXISTS trace_events_scrub_treatment
    ON cirislens.trace_events (scrub_applied_trace_level, scrub_model_digest, ts DESC)
    WHERE scrub_ner_ran IS NOT NULL;
