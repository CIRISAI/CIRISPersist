-- V088 — CC 1.13.3 anonymous-tier scope-native-privacy symbol store
--        (CIRISPersist#243 parts 1+2, v9.1.0). SQLite parity: sqlite/lens/V088.
--
-- The substrate-tier realization of CEWP FSD/SCOPE_PRIVACY §2.4: a store
-- for symbol-AEAD-encrypted RaptorQ fragments at community/family/self
-- scope. Each row is ONE encrypted symbol of a record; a record is N
-- symbols (symbol_index 0..N, N=20 default) under one record_id.
--
-- # What persist stores vs what it does NOT
--
-- Persist stores caller-pre-encrypted bytes ONLY. The XChaCha20-Poly1305
-- seal (nonce/ciphertext/tag) and the record_id / symbol_key derivation
-- are entirely CIRISEdge-side (FSD §2.4: "the caller (CIRISEdge) supplies
-- the exporter_secret"). The substrate sees opaque ciphertext + the
-- (record_id, symbol_index) addressing tuple + the community DEK epoch
-- the symbols were sealed under. This slice carries ZERO verify-crypto
-- dependency (verify stays v6.2.0); the producer side is the
-- CIRISVerify v6.3.0 scope-privacy crypto (caller-encrypted).
--
-- # Distinct from federation_blobs / put_blob_signing
--
--   - NO trust score, NO attesting_key_id: holder identity is opaque to
--     outsiders (FSD §2.4). Eviction is pure LRU + capacity (CC 1.2), NOT
--     the trust-weighted popularity×freshness decay the federation_blobs
--     sweeper uses.
--   - Primary key is (record_id, symbol_index), NOT sha256-of-plaintext.
--   - record_id is the FSD §2.4 HMAC-SHA3-256 output (32 bytes); symbols
--     are addressed by (record_id, symbol_index).
--
-- # Eviction discipline (parity with federation_blobs V053)
--
-- last_accessed_at is the LRU signal: bumped on every read (get_scope_blob
-- / list_scope_blob_symbols). The capacity-bound sweeper deletes
-- oldest-last_accessed_at first. admitted_at records the write wall-clock
-- (audit / secondary tiebreak). The two indexes mirror the federation_blobs
-- eviction-score index shape so the sweeper scan is a single ASC index walk.
--
-- This is substrate at-rest state, NOT a wire attestation — it never
-- federates and carries no signature (the secrets-path model, MISSION §1.4).
-- Refinery wraps this migration in its own transaction.

CREATE TABLE IF NOT EXISTS cirislens.federation_scope_blobs (
    -- FSD §2.4 HMAC-SHA3-256 record identifier (32 bytes).
    record_id        BYTEA NOT NULL,
    -- 0..N symbol index within the record (N=20 default). u16 on the wire;
    -- stored as INTEGER (always >= 0, fits well inside i32).
    symbol_index     INTEGER NOT NULL CHECK (symbol_index >= 0),
    -- XChaCha20-Poly1305 nonce (24 bytes, CSPRNG, caller-supplied).
    nonce            BYTEA NOT NULL,
    -- Pre-encrypted symbol bytes (opaque to the substrate).
    ciphertext       BYTEA NOT NULL,
    -- Poly1305 tag (16 bytes, caller-supplied).
    tag              BYTEA NOT NULL,
    -- The community DEK epoch the symbol was sealed under (ties to the
    -- existing community_dek_* surface via GroupDekRef; 0 for a community
    -- with no rotation row yet, exactly as community_dek_current_epoch).
    group_dek_epoch  BIGINT NOT NULL CHECK (group_dek_epoch >= 0),
    -- Write wall-clock (audit + secondary eviction tiebreak).
    admitted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- LRU signal: most-recent read wall-clock. Bumped on every read.
    last_accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (record_id, symbol_index)
);

-- Admission-order index (audit / oldest-first scans).
CREATE INDEX IF NOT EXISTS idx_federation_scope_blobs_admitted
    ON cirislens.federation_scope_blobs (admitted_at ASC);

-- LRU eviction index: the capacity sweeper scans ASC so the index returns
-- coldest (oldest-read) symbols first — single index walk, no re-sort.
CREATE INDEX IF NOT EXISTS idx_federation_scope_blobs_accessed
    ON cirislens.federation_scope_blobs (last_accessed_at ASC);

COMMENT ON TABLE cirislens.federation_scope_blobs IS
    'v9.1.0 (CIRISPersist#243, CC 1.13.3 / FSD §2.4) — caller-pre-encrypted (XChaCha20-Poly1305) RaptorQ symbol store at community/family/self scope. PK (record_id, symbol_index). LRU + capacity eviction (no trust-scoring); opaque holder identity.';
