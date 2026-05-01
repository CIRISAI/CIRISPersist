-- 002 — audit anchor columns on trace_events (FSD §3.2).
--
-- Populated only on the row where event_type = 'ACTION_RESULT'. The
-- agent already broadcasts these fields (TRACE_WIRE_FORMAT.md §5.9);
-- no agent change required for Phase 1. The anchor lets a verifier
-- recompute the per-action chain link without dragging the full
-- audit log across the wire (mission alignment: MISSION.md §2 —
-- verify/).

ALTER TABLE cirislens.trace_events
    ADD COLUMN IF NOT EXISTS audit_sequence_number BIGINT,
    ADD COLUMN IF NOT EXISTS audit_entry_hash      TEXT,
    ADD COLUMN IF NOT EXISTS audit_signature       TEXT;

CREATE INDEX IF NOT EXISTS trace_events_audit_seq
    ON cirislens.trace_events (audit_sequence_number)
    WHERE audit_sequence_number IS NOT NULL;
