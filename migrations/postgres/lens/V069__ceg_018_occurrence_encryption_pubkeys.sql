-- V069 — CEG 0.18 §5.6.8.8 recipient content-encryption pubkeys on
--        identity_occurrence (CIRISPersist#192; CIRISRegistry#69).
--
-- The substrate-wraps DEK cascade (#152, §10.1.4) wraps the content DEK to
-- each recipient's *content-encryption* keys (x25519 + ML-KEM-768, the
-- `wrap_algorithm: v2` inputs) — which are DISTINCT from the signing keys
-- (ed25519 + ML-DSA-65 in federation_keys) and from the Reticulum
-- transport x25519 in transport_destination. ML-KEM cannot be derived from
-- ML-DSA, so they must be registered as their own material.
--
-- CEG 0.18 rules them an OPTIONAL field-set on the existing
-- identity_occurrence subject_kind (parallel to transport_destination):
-- self-certified (admit requires attesting == identity or a current
-- occurrence), hybrid-signed, rotatable via `supersedes`, and already
-- cross-region replicated inside the occurrence envelope — so no new
-- subject_kind, no new replication EnvelopeKind. The occurrence is the
-- per-identity, per-region, supersedes-rotatable presence record; the
-- encryption keys are its natural home.
--
-- Nullable (hybrid-pending shape, like pubkey_ml_dsa_65_base64). An
-- occurrence with no valid ML-KEM-768 key is **fail-secure excluded** from
-- v2 grants (§10.1.4) — never a plaintext fallback; the cascade enforces
-- that at wrap time. Both halves present together or neither.

ALTER TABLE cirislens.federation_identity_occurrences
    ADD COLUMN IF NOT EXISTS pubkey_x25519_base64     TEXT,
    ADD COLUMN IF NOT EXISTS pubkey_ml_kem_768_base64 TEXT;
