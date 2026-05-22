-- V044 — `verification_source` discriminator on trace_events
-- (2.0, CIRISPersist#91 relay skip-verify path).
--
-- # Why this column exists
--
-- `IngestPipeline` step 2 verifies every CompleteTrace signature.
-- CIRISPersist#91 adds a relay skip-verify path (`VerifyMode::
-- TrustPreVerified`): a relay ingesting batches that already passed
-- an Edge authenticity gate skips persist's own per-trace
-- `verify_trace` (and its redundant federation-directory lookup) —
-- AV-9, "never re-verify what Edge verified".
--
-- `signature_verified` keeps its plain meaning — "the trace
-- signature is valid" — and stays TRUE for skip-verify rows: those
-- traces ARE authentic, Edge attested it. What changes is that we
-- now also record WHO established that authenticity:
--
--   * 'persist' — persist ran `verify_trace` itself (VerifyMode::Full,
--     the default; the only mode for untrusted direct-ingest input).
--   * 'edge'    — verification was delegated upstream; an Edge
--     verifier attested the batch and the relay carried the
--     `verify_outcome` (the VerifyMode::TrustPreVerified path).
--
-- A Lens filtering `signature_verified = TRUE` for authentic traces
-- now correctly includes relay evidence; a consumer that needs
-- persist-attested-specifically filters `verification_source =
-- 'persist'`.
--
-- # Existing rows
--
-- Every pre-V044 row was ingested through the only path that existed
-- — persist's own `verify_trace`. `DEFAULT 'persist'` backfills them
-- correctly; no data migration needed.
--
-- # Refinery wraps each migration in a transaction.

ALTER TABLE cirislens.trace_events
    ADD COLUMN IF NOT EXISTS verification_source TEXT NOT NULL DEFAULT 'persist'
        CHECK (verification_source IN ('persist', 'edge'));

COMMENT ON COLUMN cirislens.trace_events.verification_source IS
    'v2.0 (CIRISPersist#91) — who established this trace''s authenticity. ''persist'' = persist ran verify_trace (VerifyMode::Full). ''edge'' = verification delegated upstream to an Edge verifier (VerifyMode::TrustPreVerified relay skip-verify path). signature_verified stays TRUE in both cases — the signature is valid either way.';
