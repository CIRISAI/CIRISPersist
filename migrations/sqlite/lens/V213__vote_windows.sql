-- V213 — the instant this node first held a vote on an action.
-- SQLite dialect. CIRISPersist#1198 (CC 4.5.13, CC's ruling on the ticket).
--
-- POSTGRES PARITY: migrations/postgres/lens/V213__vote_windows.sql
--
-- WHY
-- ---
-- Whether a reverse-quorum steward tier is still awaiting its ruling or has
-- escalated is a window, and a window runs from the instant THIS node first
-- held the thing, as at the two-path door (V199), never from a signed instant.
-- `admitted_at` cannot be that instant: it is a serve position, re-stamped by
-- the promote sweep and every consumer-visible rewrite, and a start that moves
-- later would reopen a closed window. This table's instant never moves.
--
-- HOW
-- ---
-- One row per action, keyed by the id its objections name: an attestation id
-- or a roster row's content hash, so no foreign key. `first_held_at` is the
-- first objection held against the action, and INSERT OR IGNORE keeps it. A
-- later objection therefore cannot move the deadline.
--
-- Objections already held are backfilled from the earliest `admitted_at`
-- against each action. It is never hashed or served.

CREATE TABLE IF NOT EXISTS federation_vote_windows (
    action_id      TEXT PRIMARY KEY,
    first_held_at  TEXT NOT NULL
);

INSERT OR IGNORE INTO federation_vote_windows (action_id, first_held_at)
SELECT json_extract(attestation_envelope, '$.objects_to_attestation_id'),
       MIN(admitted_at)
  FROM federation_attestations
 WHERE json_extract(attestation_envelope, '$.dimension') = 'objection:raised:v1'
   AND COALESCE(json_extract(attestation_envelope, '$.cohort'), '') <> 'self'
   AND json_extract(attestation_envelope, '$.objects_to_attestation_id') IS NOT NULL
 GROUP BY json_extract(attestation_envelope, '$.objects_to_attestation_id');
