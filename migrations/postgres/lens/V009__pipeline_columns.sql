-- V009 — Post-ingest filter pipeline JSONB columns on trace_events
-- (v0.6.0, CIRISPersist#19).
--
-- Companion to FSD POST_INGEST_FILTER_PIPELINE.md §5.3 / §12.1. The
-- post-ingest pipeline produces three side-channel outputs that
-- consumers (RATCHET, lens-core projection, registry analytics,
-- sovereign agents) read directly off the row:
--
--   - extracted_features:  typed Features (FSD §5.4) — 16-CRC projection
--                          inputs + observation weights + step
--                          timestamps + models_used + cost/tokens.
--   - classifications:     Vec<Vec<ContentClassMatch>> — outer
--                          per-component, inner per-match within
--                          that component (FSD §6.3).
--   - pipeline_metadata:   stages_executed + per-stage timings + the
--                          edge_signature ref tying the row back to
--                          the PipelineEnvelope sidecar.
--
-- All three are NULLABLE so pre-v0.6.0 rows stay valid (rollback-safe
-- per FSD §12.7). Pipeline-aware consumers detect "no pipeline ran"
-- via `extracted_features IS NULL`.
--
-- # Indexing
--
-- No new indexes in V009. The existing trace_events indexes
-- (agent_id_hash, ts, trace_id, deployment_*) cover every query path
-- the pipeline shape introduces. JSONB GIN indexes are deferred
-- until v0.6.1 / v0.6.x where the classifications-by-class query
-- patterns crystallize (RATCHET asks first, agent dashboards next).
--
-- # Wire format note
--
-- The columns carry serde_json::Value JSONB shapes corresponding to
-- the Rust types Features / ContentClassMatch / PipelineMetadata.
-- See `src/pipeline/` for the canonical shapes. Wire stability:
-- additive-only changes within v0.6.x; breaking shape changes
-- require a schema-version bump on the per-row payload (FSD §6.3
-- uses the v0.5.x AV-24/25 scrub-envelope precedent).

BEGIN;

ALTER TABLE cirislens.trace_events
    ADD COLUMN IF NOT EXISTS extracted_features  JSONB,
    ADD COLUMN IF NOT EXISTS classifications     JSONB,
    ADD COLUMN IF NOT EXISTS pipeline_metadata   JSONB;

COMMENT ON COLUMN cirislens.trace_events.extracted_features IS
    'v0.6.0 (CIRISPersist#19) — typed Features JSONB. NULL for pre-pipeline rows.';
COMMENT ON COLUMN cirislens.trace_events.classifications IS
    'v0.6.0 (CIRISPersist#19) — Vec<Vec<ContentClassMatch>> JSONB. NULL for pre-pipeline rows.';
COMMENT ON COLUMN cirislens.trace_events.pipeline_metadata IS
    'v0.6.0 (CIRISPersist#19) — PipelineMetadata JSONB (stages, timings, sidecar ref). NULL for pre-pipeline rows.';

COMMIT;
