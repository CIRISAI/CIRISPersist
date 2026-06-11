-- V073 — CEG 1.0 §5.6.8.8.2 local content-KEM identity (CIRISPersist#198)
--        — SQLite dialect. Postgres parity: postgres/lens/V073. See that
--        file for the full design rationale.
--
-- §5.6.8.8.2 NORMATIVE: the LocalIdentityAggregate carries THREE DISTINCT
-- keypair roles (Signing / RET-transport / Content-KEM). The content-KEM
-- keypair stored here is FRESHLY GENERATED — deriving its x25519 from the
-- Ed25519 signing key would be a conformance violation.
--
-- Single-logical-row table (id=0), mirroring federation_content_master
-- (V070). The keypair is STABLE across calls/reboots: minted once on first
-- call, read back thereafter (re-minting would orphan peers' prior wraps,
-- so first-write wins). The two PRIVATE halves are sealed under the
-- content-at-rest master via at_rest_cascade::wrap_dek_for_persist
-- (base64(nonce(12) || aes256_gcm(content_master, sk))) — never cleartext.
-- HONEST about being software whenever the content-master is software.
-- v1 reads only the pubkeys; the sealed privates exist for the future
-- recipient-decrypt path (a peer wraps a DEK to our pubkeys, we unseal).
--
-- Refinery wraps this migration in its own transaction.

CREATE TABLE federation_content_kem_identity (
    id                       INTEGER PRIMARY KEY CHECK (id = 0),

    -- Honest provenance of the SEAL ('software' iff the sealing
    -- content-master is software — the only posture wired today).
    key_kind                 TEXT NOT NULL CHECK (key_kind IN ('software', 'hardware')),

    -- The two PUBLIC halves (base64 standard). x25519 = 32 raw bytes;
    -- ML-KEM-768 = 1184 raw bytes (FIPS 203).
    content_x25519_pubkey_b64       TEXT NOT NULL,
    content_ml_kem_768_pubkey_b64   TEXT NOT NULL,

    -- The two PRIVATE halves, SEALED under the content master via
    -- wrap_dek_for_persist (base64 of nonce(12) || aes256_gcm(master, sk)).
    content_x25519_privkey_sealed_b64       TEXT NOT NULL,
    content_ml_kem_768_privkey_sealed_b64   TEXT NOT NULL,

    created_at               TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);
