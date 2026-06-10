-- V069 — CEG 0.18 §5.6.8.8 recipient content-encryption pubkeys on
--        identity_occurrence (CIRISPersist#192) — SQLite dialect.
--        Postgres parity: postgres/lens/V069. See that file for rationale.
--
-- x25519 + ML-KEM-768 content-encryption pubkeys (the wrap_algorithm: v2
-- recipient inputs), distinct from signing + transport keys. Nullable,
-- hybrid-pending shape; an occurrence lacking a valid ML-KEM key is
-- fail-secure excluded from v2 grants (cascade-enforced). SQLite ALTER
-- adds one column per statement.

ALTER TABLE federation_identity_occurrences ADD COLUMN pubkey_x25519_base64 TEXT;
ALTER TABLE federation_identity_occurrences ADD COLUMN pubkey_ml_kem_768_base64 TEXT;
