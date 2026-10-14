-- V194 — hard_case_events becomes a projection of hard_case:{kind}:v1 rows.
-- Postgres dialect. v57.0.0 (CIRISPersist#988 item 2; CC 3.1.9.4, CC 2.4.2).
--
-- SQLITE PARITY: migrations/sqlite/lens/V194__hard_case_events_projection.sql
--
-- WHY
-- ---
-- V075 made hard_case_events the substrate's emission surface: written
-- directly, unsigned, the only copy. CC 3.1.9.4 registers hard_case:{kind}
-- as a dimension, so every event is now a `scores` row on the plane
-- (attester = the node key; `attestation_admit::plan_hard_case_row`), and
-- this table is the projection of those rows, written by the row's executor
-- in the same transaction and rebuildable from the rows alone
-- (CLM-silo-projection-rebuildable).
--
-- HOW
-- ---
-- `attestation_id` names the row each projection row comes from. ON DELETE
-- CASCADE: a row that leaves takes its projection row with it, so no door
-- that deletes rows can leave the projection ahead of the plane. A pre-v57
-- row carries NULL until the first emitter after the upgrade rehomes it
-- (`rehome_legacy_hard_case_events`, with the node's key in hand); the
-- partial index makes that "any left?" probe free.

ALTER TABLE cirislens.hard_case_events
    ADD COLUMN IF NOT EXISTS attestation_id TEXT
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

CREATE UNIQUE INDEX IF NOT EXISTS hard_case_events_by_attestation
    ON cirislens.hard_case_events (attestation_id);

CREATE INDEX IF NOT EXISTS hard_case_events_legacy
    ON cirislens.hard_case_events (event_id) WHERE attestation_id IS NULL;
