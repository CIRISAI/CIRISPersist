-- V167 — unlabelled delegations a node already holds keep their reading, SQLite dialect
-- CIRISPersist#973 (CC 3.2 T4a, steward ruling 2026-10-01: "bundle only")
--
-- POSTGRES PARITY: migrations/postgres/lens/V167__trust_direction_held.sql
--
-- WHAT AND WHY
-- ------------
-- CC 3.2 T4a: "A new row with no `trust:{job}` label gives no acceptance and
-- is no charter ... Unlabelled rows a node already holds keep their reading
-- under T4." A `delegates_to` row with no `trust:charter:v1` /
-- `trust:accepts:v1` / `trust:confers:v1` label used to be read as a charter
-- or an acceptance edge from its DIRECTION alone, so omitting the label
-- skipped the attach gate.
--
-- "Already holds" has to be a fact this node recorded, not something a reader
-- infers from a signer-chosen instant. This table is that fact: the ids of
-- the unlabelled `delegates_to` rows stored BEFORE this migration ran. The
-- trust-root readers keep reading those rows by direction; an unlabelled row
-- admitted afterwards is in neither this table nor the pinned bundle, and is
-- read as no charter and no acceptance edge. Nothing is ever inserted here
-- after the migration: the set only ever means "held when the rule arrived".

CREATE TABLE federation_trust_direction_held (
    attestation_id TEXT PRIMARY KEY
);

INSERT INTO federation_trust_direction_held (attestation_id)
SELECT attestation_id FROM federation_attestations
 WHERE attestation_type = 'delegates_to'
   AND COALESCE(json_extract(attestation_envelope, '$.dimension'), '')
       NOT IN ('trust:charter:v1', 'trust:accepts:v1', 'trust:confers:v1');
