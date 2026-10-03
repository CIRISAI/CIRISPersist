-- V167 — unlabelled delegations a node already holds keep their reading, Postgres dialect
-- CIRISPersist#973 (CC 3.2 T4a, steward ruling 2026-10-01: "bundle only")
--
-- SQLITE PARITY: migrations/sqlite/lens/V167__trust_direction_held.sql
--
-- See the sqlite file for the full rationale. The ids of the unlabelled
-- `delegates_to` rows stored BEFORE this migration ran: the trust-root readers
-- keep reading those by direction (CC 3.2 T4); an unlabelled row admitted
-- afterwards is no charter and no acceptance edge unless it is a member of
-- the pinned GenesisBundle. Nothing is inserted here after the migration.

CREATE TABLE IF NOT EXISTS cirislens.federation_trust_direction_held (
    attestation_id TEXT PRIMARY KEY
);

INSERT INTO cirislens.federation_trust_direction_held (attestation_id)
SELECT attestation_id FROM cirislens.federation_attestations
 WHERE attestation_type = 'delegates_to'
   AND COALESCE(attestation_envelope::jsonb ->> 'dimension', '')
       NOT IN ('trust:charter:v1', 'trust:accepts:v1', 'trust:confers:v1')
ON CONFLICT (attestation_id) DO NOTHING;
