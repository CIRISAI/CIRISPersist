-- V202 — every hard_case_events row names the node that emitted it.
-- SQLite dialect. v60.0.0 (CIRISConstitution#170 closed; CC 3.1.9.4).
--
-- POSTGRES PARITY: migrations/postgres/lens/V202__hard_case_event_emitter.sql
--
-- WHY
-- ---
-- The hold that kept hard_case:{kind}:v1 rows at the local tier is lifted:
-- the rows replicate, a peer's row projects on receipt, and the listing now
-- holds other nodes' events beside this node's own. A widened read set
-- carries the floor it crosses: each projection row names its emitter, the
-- key that SIGNED its row (`attesting_key_id`), never anything from `detail`
-- (`hard_case::project_hard_case_row` sets it; the filter selects on it).
--
-- HOW
-- ---
-- Rows already projected take their row's signer. A pre-v57 silo row
-- (attestation_id NULL) stays NULL until the rehome moves it onto a signed
-- row, whose projection carries the emitter.

ALTER TABLE hard_case_events ADD COLUMN emitter_key_id TEXT;

UPDATE hard_case_events
   SET emitter_key_id = (
       SELECT a.attesting_key_id FROM federation_attestations a
        WHERE a.attestation_id = hard_case_events.attestation_id)
 WHERE attestation_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS hard_case_events_by_emitter
    ON hard_case_events (emitter_key_id, emitted_at);
