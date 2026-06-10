-- V070 — CEG 0.18 §10.1.4 self/family at-rest DEK cascade — the
--        per-recipient key_grant delivery table (CIRISPersist#152) —
--        SQLite dialect. Postgres parity: postgres/lens/V070. See that
--        file for the full design rationale.
--
-- The `InvisibleEncrypted` (self/family) at-rest tier: persist generates
-- a fresh per-write DEK, AES-256-GCM-encrypts the blob body into a
-- self-describing versioned envelope (stored in federation_blobs keyed
-- on the *ciphertext* SHA-256 — the at-rest content address), and wraps
-- that DEK to every active recipient occurrence via wrap_algorithm: v2
-- (x25519 + ML-KEM-768). Each wrap is one row here.
--
-- This is substrate state, NOT a wire attestation — it never federates,
-- carries no signature, and is the at-rest analogue of the secrets
-- store's per-secret rows (the secrets-path model, MISSION §1.4). It is
-- distinct from the cirisnode.contributions `key_grant` wire surface
-- (V054/V064), which is the federated streaming/media-sharing cascade.
--
-- Two row kinds share the table, discriminated by `wrap_algorithm`:
--   1. recipient grants — `wrap_algorithm = 'x25519_mlkem768_aes256_gcm_hkdf_sha256'`,
--      `recipient_key_id` = the occurrence's federation key. `wrapped_dek`
--      is the KeyGrantWrapV2 JSON envelope. Fail-secure: a recipient with
--      no valid encryption_pubkeys gets NO row (never plaintext).
--   2. persist self-retention — `recipient_key_id = '__persist_self__'`,
--      `wrap_algorithm = 'aes256_gcm_content_master'`. `wrapped_dek` is
--      `nonce(12) || aes256_gcm(content_master_key, dek)`, letting persist
--      recover the DEK to serve get_blob_for_viewer in the default tier
--      (OQ-4: "persist holds the DEK"). The content master key is
--      hardware-rooted (HKDF over a sealed seed, the secrets-store root
--      under a distinct context), software-fallback honest-about-software.
--
-- Append-only; the row set for an at_rest_sha grows as members are added
-- (the #161 Ask-2 retroactive ADD walk) and is never rewritten on remove
-- (forward secrecy is automatic — the per-write fresh DEK means a removed
-- member keeps only the grants for content it already had).
--
-- Refinery wraps this migration in its own transaction.

CREATE TABLE federation_blob_key_grants (
    -- The at-rest content address: SHA-256 of the stored ciphertext
    -- envelope (NOT the plaintext sha). References the federation_blobs row.
    at_rest_sha256       BLOB NOT NULL
        CHECK (length(at_rest_sha256) = 32),

    -- Recipient federation key_id (an occurrence_key_id for self/family
    -- recipients), or the reserved '__persist_self__' sentinel for
    -- persist's own content-master self-retention row.
    recipient_key_id     TEXT NOT NULL,

    -- 'x25519_mlkem768_aes256_gcm_hkdf_sha256' (recipient v2 grant) or
    -- 'aes256_gcm_content_master' (persist self-retention).
    wrap_algorithm       TEXT NOT NULL
        CHECK (wrap_algorithm IN (
            'x25519_mlkem768_aes256_gcm_hkdf_sha256',
            'aes256_gcm_content_master'
        )),

    -- The wrapped DEK. For v2 grants: the KeyGrantWrapV2 JSON envelope
    -- (base64 fields). For the self-retention row: base64 of
    -- nonce(12) || aes256_gcm(content_master, dek).
    wrapped_dek          TEXT NOT NULL,

    -- The cohort_scope the originating write carried ('self' | 'family').
    -- Informational / audit; the grant itself is scope-agnostic at read.
    cohort_scope         TEXT NOT NULL,

    created_at           TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),

    PRIMARY KEY (at_rest_sha256, recipient_key_id)
);

-- The get_blob_for_viewer hot path: "is there a grant for (sha, viewer)?".
CREATE INDEX federation_blob_key_grants_by_recipient
    ON federation_blob_key_grants (recipient_key_id);

-- ── content-at-rest master key (software default) ──────────────────
--
-- The DEK-retention root for the default tier (OQ-4). PRODUCTION TARGET
-- is the hardware-rooted derivation (HKDF over a TPM/Keystore/Secure-
-- Enclave-sealed seed via ciris_verify_core::derive_symmetric_key under
-- CONTENT_MASTER_CONTEXT — the secrets-store root, distinct context), per
-- ENCRYPTED_AT_REST.md §4.3. Wiring that hardware seed through the Engine
-- is a follow-up (#152 P-next). Until then this single-row table holds a
-- software content-master generated once on first encrypted write —
-- HONEST about being software (key_kind='software'), exactly the
-- posture secrets/ takes on a no-TPM host (SecretsError::HardwareKey-
-- Unavailable → "stay on the software master key"). FDE remains the
-- at-rest posture for the master itself on a software host.
--
-- Single-logical-row table (id=0). master_key_b64 is the 32-byte AES key.
CREATE TABLE federation_content_master (
    id              INTEGER PRIMARY KEY CHECK (id = 0),
    key_kind        TEXT NOT NULL CHECK (key_kind IN ('software', 'hardware')),
    master_key_b64  TEXT,            -- present iff key_kind='software'
    descriptor      TEXT NOT NULL,   -- provenance string
    created_at      TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);
