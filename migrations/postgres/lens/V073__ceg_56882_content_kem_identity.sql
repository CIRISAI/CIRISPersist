-- V073 — CEG 1.0 §5.6.8.8.2 local content-KEM identity (CIRISPersist#198).
--        The persist-minted, persist-sealed content-encryption keypair
--        that fills the **content-KEM role** of the LocalIdentityAggregate.
--        SQLite parity: sqlite/lens/V073.
--
-- §5.6.8.8.2 is NORMATIVE: the LocalIdentityAggregate carries THREE
-- DISTINCT keypair roles —
--   1. Signing       (Ed25519 + ML-DSA-65)  — persist's local signer
--   2. RET-transport (X25519 + Ed25519)     — edge (#199, not in v1)
--   3. Content-KEM   (X25519 + ML-KEM-768)  — persist mints + seals (here)
-- "Deriving the content-KEM x25519 from either of the others is a
-- conformance violation." So the keypair stored here is FRESHLY GENERATED
-- (ciris_crypto::x25519::generate_ephemeral_keypair +
-- ciris_crypto::ml_kem::generate_keypair) — independent of the signing
-- key, never an Edwards→Montgomery conversion of it.
--
-- This is the SAME content-KEM shape an IdentityOccurrence registers as a
-- wrap target (V069 encryption_pubkeys / EncryptionPubkeys), but for the
-- LOCAL node's own identity — so a peer can wrap an at-rest DEK to *this*
-- node's content-KEM pubkeys.
--
-- Single-logical-row table (id=0), mirroring federation_content_master
-- (V070). The keypair is STABLE across calls/reboots: it is minted once on
-- first call and read back thereafter. Re-minting would orphan every grant
-- a peer has already wrapped to the prior pubkeys, so first-write wins (the
-- INSERT is ON CONFLICT DO NOTHING and the persisted row is read back).
--
-- ── private-key sealing ────────────────────────────────────────────
-- The two PRIVATE halves are NOT stored in cleartext. They are sealed
-- under persist's content-at-rest master key (federation_content_master,
-- V070) via the SAME AES-256-GCM discipline the self/family DEK cascade
-- uses for self-retention: at_rest_cascade::wrap_dek_for_persist, i.e.
-- base64(nonce(12) || aes256_gcm(content_master, private_key_bytes)).
-- HONEST about being software whenever the content-master is software
-- (key_kind mirrors the master's posture). The sealed privates are stored
-- for the FUTURE at-rest-recipient decrypt path (a peer wraps a DEK to our
-- content-KEM pubkeys; we unseal to decrypt) — NOT exercised in v1, which
-- only needs the two pubkeys for the aggregate.
--
-- Refinery wraps this migration in its own transaction.

CREATE TABLE IF NOT EXISTS cirislens.federation_content_kem_identity (
    id                       INTEGER PRIMARY KEY CHECK (id = 0),

    -- Honest provenance of the SEAL: 'software' iff the content-master that
    -- sealed the privates is software (the only posture wired today).
    key_kind                 TEXT NOT NULL CHECK (key_kind IN ('software', 'hardware')),

    -- The two PUBLIC halves (base64 standard alphabet). x25519 = 32 raw
    -- bytes; ML-KEM-768 = 1184 raw bytes (FIPS 203). These are what the
    -- aggregate publishes and what peers wrap to.
    content_x25519_pubkey_b64       TEXT NOT NULL,
    content_ml_kem_768_pubkey_b64   TEXT NOT NULL,

    -- The two PRIVATE halves, SEALED under the content master via
    -- wrap_dek_for_persist (base64 of nonce(12) || aes256_gcm(master, sk)).
    -- Never cleartext. Stored for the future recipient-decrypt path.
    content_x25519_privkey_sealed_b64       TEXT NOT NULL,
    content_ml_kem_768_privkey_sealed_b64   TEXT NOT NULL,

    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
