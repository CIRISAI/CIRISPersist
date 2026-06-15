-- V080 — detection_events Art. 17 erasure tombstone (CIRISPersist#222).
--        Postgres dialect. SQLite parity: sqlite/lens/V080.
--
-- GDPR Art. 17 / DSAR — `Engine::delete_traces_for_agent_id_hash` HARD-
-- deletes the subject's `trace_events` + `trace_llm_calls`, but the
-- derived `cirislens_derived.detection_events` rows are NOT the subject's
-- personal data — they are substrate-derived analytics (a detector's
-- triage verdict over a cohort). The operator decision for Art. 17
-- (CIRISPersist#222) is to TOMBSTONE the derived detections, not hard-
-- delete them: keep the detection/audit record (detector, severity,
-- cohort_cell, reproducibility anchors) while SEVERING the PII linkage to
-- the erased trace.
--
-- ═══ The PII linkage that gets severed ═══
--
-- detection_events has NO `agent_id_hash` column. Its linkage to the
-- erased agent's traces is via the forensic join keys:
--   * `trace_id`        — directly names the agent's trace (V001 dedup key
--                          is gated on agent_id_hash, so trace_id resolves
--                          back to the subject).
--   * `body_sha256`     — SHA-256 of the agent's original wire body (a
--                          hash OF the subject's PII; the forensic join key).
--   * `canonical_bytes` — the signed canonical JSON, which embeds the
--                          trace_id + body content (re-derivable PII linkage).
-- The tombstone NULLs all three and stamps `erased_at`. detector,
-- severity, cohort_cell, conformity_*, lens_core_version,
-- ratchet_calibration_version, signing_key_id and the signature columns
-- stay — the analytics survive; the re-verifiability of the signature
-- over the (now-NULLed) canonical_bytes is knowingly forfeited as the
-- cost of erasure (the signature columns are retained as audit residue,
-- not as a live verification target).
--
-- ═══ Why nullable + retain-row over hard-delete ═══
--
-- A tombstoned row preserves the fleet-wide detection statistics
-- (CIRISLensCore consumes detection counts/severities for calibration)
-- without retaining a single byte that links a detection to the erased
-- subject. A `WHERE erased_at IS NULL` predicate lets read paths exclude
-- tombstones from PII-bearing joins while still counting them as anonymous
-- analytics.
--
-- The three redacted columns are made NULLABLE (they were NOT NULL on
-- V008). The length / bound CHECK constraints (octet_length(...) = N)
-- are UNAFFECTED: a CHECK evaluates to UNKNOWN (= passes) when its column
-- is NULL, so a tombstoned NULL row satisfies every existing CHECK. No
-- constraint drop is required beyond the NOT NULL relaxation.

BEGIN;

ALTER TABLE cirislens_derived.detection_events
    ALTER COLUMN trace_id        DROP NOT NULL,
    ALTER COLUMN body_sha256     DROP NOT NULL,
    ALTER COLUMN canonical_bytes DROP NOT NULL;

ALTER TABLE cirislens_derived.detection_events
    ADD COLUMN IF NOT EXISTS erased_at TIMESTAMPTZ;

-- Partial index: erasure sweeps + tombstone-exclusion read predicates
-- only ever care about the tombstoned set, which is sparse.
CREATE INDEX IF NOT EXISTS detection_events_erased_at
    ON cirislens_derived.detection_events (erased_at)
    WHERE erased_at IS NOT NULL;

COMMENT ON COLUMN cirislens_derived.detection_events.erased_at IS
    'V080 (CIRISPersist#222) — Art. 17 tombstone marker. NON-NULL = the PII linkage (trace_id, body_sha256, canonical_bytes) was NULLed by delete_traces_for_agent_id_hash; the detection analytics (detector/severity/cohort_cell) are retained.';

COMMIT;
