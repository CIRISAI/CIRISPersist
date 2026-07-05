-- V096 — #383 multi-scrub canonical record: the 2nd..Nth anchor scrub
-- signatures (CC 3.4.7.1 / FSD Trust Root / CIRISVerify#174) (Postgres dialect).
--
-- # Why this column
--
-- v13.0.0 (#372) made the `canonical` identity_type role add-only via
-- `check_canonical_role_admission`, but ADD was **1-of-N**: a single
-- anchor-scrub (`scrub_key_id ∈ anchor`) conferred `canonical`. That makes the
-- founding trust anchor the weakest-authority object in the mesh — one captured
-- accord key mints a rogue canonical server (the ASI first-strike hole). #383
-- flips ADD to **2-of-3**: `canonical` is conferred only on a record with ≥2
-- DISTINCT anchor holders each carrying a cryptographically VALID scrub
-- signature over the SAME canonical `registration_envelope`.
--
-- The scrub *set* lives OUTSIDE the byte-identical signed envelope (a 1-scrub
-- and a 2-scrub record of the same target canonicalize identically — only the
-- scrub set differs), so persist carries it ADDITIVELY: scrub #1 stays in the
-- existing `scrub_key_id` / `scrub_signature_classical` / `scrub_signature_pqc`
-- columns; scrubs #2..N ride this new column as a JSON array of
-- `{scrub_key_id, scrub_signature_classical, scrub_signature_pqc?}`
-- (`KeyRecord.additional_scrubs`, wire-identical to `ciris_verify_core` v8.9.0).
--
-- # Shape
--
-- TEXT holding a JSON array; DEFAULT '[]' and NULL-tolerant (a legacy /
-- single-scrub row reads back as an empty set). An empty array serializes away
-- (`skip_serializing_if`) so a single-scrub record's `persist_row_hash` stays
-- byte-identical to the pre-#383 shape.
--
-- No TimescaleDB (operator directive): plain postgres:16, ordinary ADD COLUMN.
-- No explicit BEGIN/COMMIT — refinery wraps each migration in a transaction.

ALTER TABLE cirislens.federation_keys
    ADD COLUMN IF NOT EXISTS additional_scrubs TEXT NOT NULL DEFAULT '[]';

COMMENT ON COLUMN cirislens.federation_keys.additional_scrubs IS
    'V096 (CIRISPersist#383, CC 3.4.7.1 / CIRISVerify#174) — the 2nd..Nth anchor scrub signatures over the SAME canonical registration_envelope, as a JSON array of {scrub_key_id, scrub_signature_classical, scrub_signature_pqc?} (KeyRecord.additional_scrubs). Scrub #1 stays in scrub_key_id/scrub_signature_*. The `canonical` role is conferred only on a record whose scrub set has >=2 distinct anchor holders with VALID signatures (the 2-of-3 add gate); root_binding still roots via any one scrub. DEFAULT ''[]'' — an empty set serializes away so a single-scrub row''s persist_row_hash is byte-identical to pre-#383.';
