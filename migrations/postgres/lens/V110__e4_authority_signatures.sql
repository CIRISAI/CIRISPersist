-- V110 (CIRISPersist#502 E4 followup) — persist the authority signature the
-- E4 gate already verifies-then-discards. Postgres dialect. SQLite parity:
-- sqlite/lens/V110. See that file for the full rationale.

ALTER TABLE cirislens.federation_families ADD COLUMN authority_key_id TEXT;
ALTER TABLE cirislens.federation_families ADD COLUMN scrub_signature_classical TEXT;
ALTER TABLE cirislens.federation_families ADD COLUMN scrub_signature_pqc TEXT;

ALTER TABLE cirislens.federation_communities ADD COLUMN authority_key_id TEXT;
ALTER TABLE cirislens.federation_communities ADD COLUMN scrub_signature_classical TEXT;
ALTER TABLE cirislens.federation_communities ADD COLUMN scrub_signature_pqc TEXT;

ALTER TABLE cirislens.federation_family_membership_revocations ADD COLUMN authority_key_id TEXT;
ALTER TABLE cirislens.federation_family_membership_revocations ADD COLUMN scrub_signature_classical TEXT;
ALTER TABLE cirislens.federation_family_membership_revocations ADD COLUMN scrub_signature_pqc TEXT;

ALTER TABLE cirislens.federation_community_membership_revocations ADD COLUMN authority_key_id TEXT;
ALTER TABLE cirislens.federation_community_membership_revocations ADD COLUMN scrub_signature_classical TEXT;
ALTER TABLE cirislens.federation_community_membership_revocations ADD COLUMN scrub_signature_pqc TEXT;

ALTER TABLE cirislens.federation_location_proofs ADD COLUMN authority_key_id TEXT;
ALTER TABLE cirislens.federation_location_proofs ADD COLUMN scrub_signature_classical TEXT;
ALTER TABLE cirislens.federation_location_proofs ADD COLUMN scrub_signature_pqc TEXT;
