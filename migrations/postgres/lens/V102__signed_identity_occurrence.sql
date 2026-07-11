-- V102 — CIRISPersist#418 (occurrence-KEX arc 2/4): the signed-occurrence
--        columns. Postgres dialect. SQLite parity: sqlite/lens/V102.
--
-- put_identity_occurrence now verifies a hybrid signature over the exact
-- producer envelope (verify_transport_binding, CIRISVerify#183) before admitting
-- the content-tier KEX pubkeys, closing the silent content-MITM. These columns
-- persist the authenticated material (see the SQLite twin for the full rationale).
-- All nullable: pre-#418 rows grandfather to NULL; the WIRE path rejects unsigned.

ALTER TABLE cirislens.federation_identity_occurrences ADD COLUMN IF NOT EXISTS attesting_key_id  TEXT;
ALTER TABLE cirislens.federation_identity_occurrences ADD COLUMN IF NOT EXISTS signed_envelope   JSONB;
ALTER TABLE cirislens.federation_identity_occurrences ADD COLUMN IF NOT EXISTS signature         JSONB;
ALTER TABLE cirislens.federation_identity_occurrences ADD COLUMN IF NOT EXISTS transport_binding JSONB;
