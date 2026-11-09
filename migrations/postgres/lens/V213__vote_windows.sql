-- V213 — the instant this node first held a vote on an action.
-- Postgres dialect. CIRISPersist#1198 (CC 4.5.13, CC's ruling on the ticket).
--
-- SQLITE PARITY: migrations/sqlite/lens/V213__vote_windows.sql, which carries
-- the reasoning. `admitted_at` is a serve position that rewrites re-stamp, so
-- a window cannot start there: a start that moves later reopens a closed
-- window. This table's instant never moves.

CREATE TABLE IF NOT EXISTS cirislens.federation_vote_windows (
    action_id      TEXT PRIMARY KEY,
    first_held_at  TIMESTAMPTZ NOT NULL
);

INSERT INTO cirislens.federation_vote_windows (action_id, first_held_at)
SELECT attestation_envelope::jsonb ->> 'objects_to_attestation_id',
       MIN(admitted_at)
  FROM cirislens.federation_attestations
 WHERE attestation_envelope::jsonb ->> 'dimension' = 'objection:raised:v1'
   AND COALESCE(attestation_envelope::jsonb ->> 'cohort', '') <> 'self'
   AND attestation_envelope::jsonb ->> 'objects_to_attestation_id' IS NOT NULL
 GROUP BY attestation_envelope::jsonb ->> 'objects_to_attestation_id'
ON CONFLICT (action_id) DO NOTHING;
